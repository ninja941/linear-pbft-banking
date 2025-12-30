package com.distributedsystems.pbft.service;

import com.distributedsystems.pbft.client.ReplicaClient;
import com.distributedsystems.pbft.model.ClientAccountEntity;
import com.distributedsystems.pbft.model.ReplicaLogEntity;
import com.distributedsystems.pbft.persistence.ReplicaLogEntry;
import com.distributedsystems.pbft.proto.ClientReply;
import com.distributedsystems.pbft.proto.ClientRequest;
import com.distributedsystems.pbft.proto.PrePrepare;
import com.distributedsystems.pbft.repository.IReplicatLogRepository;
import com.distributedsystems.pbft.repository.IClientAccountRepository;
import com.distributedsystems.pbft.state.NodeState;
import com.google.protobuf.util.JsonFormat;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.List;
import java.util.NavigableSet;
import java.util.Optional;
import java.util.concurrent.ConcurrentSkipListSet;

@Slf4j
@Service
@RequiredArgsConstructor
public class ExecutionServiceImpl {

    private final NodeState nodeState;
    private final IClientAccountRepository accountRepo;
    private final ReplicaLogEntry replicaLogEntry;
    private final IReplicatLogRepository replicaLogRepo;
    private final CheckpointService checkpointService;
    private final ReplicaClient replicaClient;
    

    private final NavigableSet<Long> deferredLog = new ConcurrentSkipListSet<>();


    @Transactional
    public ClientReply execute(long seq) {
        final long want = nodeState.getLastExecutedSequenceNumber() + 1;
        if (seq != want) {
            deferredLog.add(seq);

            return reply(seq, "DEFERRED", "Out-of-order; need Se=" + want);
        }

        ClientReply r = executeInternal(seq);
        drainDeferred();
        return r;
    }

    @Transactional
    public void drainDeferred() {
        while (true) {
            long next = nodeState.getLastExecutedSequenceNumber() + 1;
            if (!deferredLog.remove(next)) break; // next not ready
            executeInternal(next);
        }
    }

    @Transactional
    protected ClientReply executeInternal(long seq) {
        try {
            Optional<PrePrepare> preOpt = nodeState.getPrePrepareLog(seq);
            if (preOpt.isEmpty()) {
                try {
                    var rowOpt = replicaLogRepo.findById(seq);
                    if (rowOpt.isPresent() && rowOpt.get().getPrePreparePayload() != null) {
                        var row = rowOpt.get();
                        String json = row.getPrePreparePayload();
                        ClientRequest.Builder rb = ClientRequest.newBuilder();
                        JsonFormat.parser().ignoringUnknownFields().merge(json, rb);
                        ClientRequest req = rb.build();
                        PrePrepare synthetic = PrePrepare.newBuilder()
                                .setView(row.getViewNumber())
                                .setSequence(seq)
                                .setDigest(row.getPrePrepareDigest() == null ? "" : row.getPrePrepareDigest())
                                .setRequest(req)
                                .setLeaderId(nodeState.validPrimaryIdForView(row.getViewNumber()))
                                .build();

                        return performAndRecord(seq, synthetic);
                    }
                } catch (Exception ex) {
                    log.error("[{}] Fallback reconstruction failed for seq={} → {}",
                            nodeState.getSelfNodeId(), seq, ex.getMessage(), ex);
                }

                deferredLog.add(seq);

                return reply(seq, "", "");
            }

            if (nodeState.getLastExecutedSequenceNumber() >= seq) {

                return reply(seq, "", "");
            }
            return performAndRecord(seq, preOpt.get());

        } catch (Exception e) {
            return reply(seq, "FAIL", e.getMessage());
        }
    }

    private ClientReply performAndRecord(long seq, PrePrepare pre) throws Exception {
        ClientRequest req = pre.getRequest();
        String digest = pre.getDigest() == null ? "" : pre.getDigest();
        Optional<String> priorResultOpt = priorExecutionResult(digest);
        if (priorResultOpt.isPresent()) {
            String priorResult = priorResultOpt.get();
            log.info("[{}] Duplicate request digest={} already executed → skipping side effects (seq={})",
                    nodeState.getSelfNodeId(), digest, seq);

            String reqJson = JsonFormat.printer().omittingInsignificantWhitespace().print(req);
            replicaLogEntry.upsert(
                    seq,
                    (int) pre.getView(),
                    digest,
                    ReplicaLogEntity.Phase.EXECUTED,
                    true,
                    reqJson,
                    digest,
                    reqJson,
                    priorResult
            );

            nodeState.setLastExecutedSequenceNumber(seq);
            nodeState.setLastCommitSequenceNumber((int) seq);
            checkpointService.afterCommitMaybeCheckpoint(seq);
            checkpointService.processDeferredProofs(seq);
            nodeState.markProgress();

            ClientReply duplicateReply = reply(seq, priorResult, "Duplicate request replayed");
            sendClientReply(req, duplicateReply);
            return duplicateReply;
        }

        ClientReply result = performExecution(pre);

        String reqJson = JsonFormat.printer().omittingInsignificantWhitespace().print(req);

        replicaLogEntry.upsert(
                seq,
                (int) pre.getView(),
                pre.getDigest(),
                ReplicaLogEntity.Phase.EXECUTED,
                true,
                reqJson,
                pre.getDigest(),
                reqJson,
                result.getResult()
        );

        nodeState.setLastExecutedSequenceNumber(seq);
        nodeState.setLastCommitSequenceNumber((int) seq);

        checkpointService.afterCommitMaybeCheckpoint(seq);
        checkpointService.processDeferredProofs(seq);

        nodeState.markProgress();

        log.info("[{}] Executed seq={} op={} → {}",
                nodeState.getSelfNodeId(), seq, req.getOperation(), result.getResult());
        sendClientReply(req, result);

        return result;
    }

    private void sendClientReply(ClientRequest req, ClientReply result) {
        try {
            String clientId = req.getClientId();
            if (clientId != null && !clientId.isEmpty()) {
                ClientReply replyMsg = ClientReply.newBuilder()
                        .setClientId(clientId)
                        .setSequence(result.getSequence())
                        .setReplicaId(nodeState.getSelfNodeId())
                        .setResult(result.getResult())
                        .build();

                replicaClient.sendClientReply(replyMsg);
                log.info("[{}] Sent {} reply to {}", nodeState.getSelfNodeId(), replyMsg.getResult(), clientId);
            } else {

            }
        } catch (Exception sendErr) {

        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    protected ClientReply performExecution(PrePrepare pre) {
        ClientRequest req = pre.getRequest();
        String op = Optional.ofNullable(req.getOperation()).orElse("").trim().toUpperCase();

        return switch (op) {
            case "TRANSFER" -> handleTransfer(pre, req);
            case "BALANCE"  -> handleBalance(pre, req);
            default -> {
                log.warn("[{}] Unknown operation '{}' (seq={})",
                        nodeState.getSelfNodeId(), op, pre.getSequence());
                yield reply(pre.getSequence(), "UNKNOWN_OP", "Unsupported operation");
            }
        };
    }

    @Transactional
    protected ClientReply handleTransfer(PrePrepare pre, ClientRequest req) {
        String from = req.getFromAccount();
        String to = req.getToAccount();
        long amount = req.getAmount();

        List<ClientAccountEntity> accounts = accountRepo.findAll(Sort.by("name"));

        ClientAccountEntity sender = accounts.stream()
                .filter(a -> a.getName().equals(from))
                .findFirst()
                .orElseGet(() -> new ClientAccountEntity(null, from, 0L));

        ClientAccountEntity receiver = accounts.stream()
                .filter(a -> a.getName().equals(to))
                .findFirst()
                .orElseGet(() -> new ClientAccountEntity(null, to, 0L));

        if (sender.getBalance() < amount) {
            long have = sender.getBalance();
            long need = amount;
            String msg = "Insufficient funds: " + have + " < " + need;
            log.warn("[{}] TRANSFER {} → {} amt={} rejected: insufficient funds (have={}, need={})",
                    nodeState.getSelfNodeId(), from, to, amount, have, need);
            return reply(pre.getSequence(), "FAIL", msg);
        }

        sender.setBalance(sender.getBalance() - amount);
        receiver.setBalance(receiver.getBalance() + amount);
        accountRepo.save(sender);
        accountRepo.save(receiver);
        accountRepo.flush();

        log.info("[{}] TRANSFER {} → {} amt={}  balances: {}={}  {}={}",
                nodeState.getSelfNodeId(), from, to, amount,
                from, sender.getBalance(), to, receiver.getBalance());

        return reply(pre.getSequence(), "OK", "Transferred " + amount);
    }

    @Transactional(readOnly = true)
    protected ClientReply handleBalance(PrePrepare pre, ClientRequest req) {
        String who = req.getFromAccount();
        long balance = accountRepo.findByName(who)
                .map(ClientAccountEntity::getBalance)
                .orElse(0L);

        log.info("[{}] BALANCE {} = {}", nodeState.getSelfNodeId(), who, balance);
        return reply(pre.getSequence(), "BALANCE=" + balance, "Balance of " + who + " = " + balance);
    }

    private ClientReply reply(long seq, String result, String msg) {
        return ClientReply.newBuilder()
                .setSequence(seq)
                .setResult(result)
                .setReplicaId(nodeState.getSelfNodeId())
                .setClientId("client")
                .build();
    }

    public void resetDeduplicationCaches() {
        deferredLog.clear();
    }

    private Optional<String> priorExecutionResult(String digest) {
        if (digest == null || digest.isBlank()) return Optional.empty();
        try {
            List<ReplicaLogEntity> matches = replicaLogRepo.findByDigest(digest);
            if (matches == null || matches.isEmpty()) {
                return Optional.empty();
            }

            Comparator<ReplicaLogEntity> executedOrdering = Comparator
                    .comparing(ReplicaLogEntity::getLastUpdated,
                            Comparator.nullsFirst(Comparator.naturalOrder()))
                    .thenComparingLong(ReplicaLogEntity::getSequenceNumber);

            return matches.stream()
                    .filter(row -> row.getPhase() != null
                            && row.getPhase().ordinal() >= ReplicaLogEntity.Phase.EXECUTED.ordinal())
                    .max(executedOrdering)
                    .map(row -> {
                        String res = row.getExecResult();
                        return (res == null || res.isBlank()) ? "OK" : res;
                    });
        } catch (Exception e) {

        }
        return Optional.empty();
    }
}
