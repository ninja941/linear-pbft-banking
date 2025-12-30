package com.distributedsystems.pbft.service;

import com.distributedsystems.pbft.client.ReplicaClient;
import com.distributedsystems.pbft.exe.ClusterConfig;
import com.distributedsystems.pbft.model.CheckpointEntity;
import com.distributedsystems.pbft.model.ClientAccountEntity;
import com.distributedsystems.pbft.persistence.KeyManager;
import com.distributedsystems.pbft.persistence.ReplicaLogEntry;
import com.distributedsystems.pbft.proto.*;
import com.distributedsystems.pbft.repository.ICheckpointRepository;
import com.distributedsystems.pbft.repository.IClientAccountRepository;
import com.distributedsystems.pbft.state.NodeState;
import com.distributedsystems.pbft.util.CryptoUtil;
import com.google.protobuf.util.JsonFormat;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class CheckpointService {

    private final ApplicationContext appContext;
    private final ReplicaLogEntry replicaLogEntry;
    private final IClientAccountRepository accountRepo;
    private final ICheckpointRepository checkpointRepo;
    private final NodeState nodeState;
    private final KeyManager keyManager;
    private final ByzantineService byzantineService;
    private final ReplicaClient replicaClient;
    private final EntityManager entityManager;

    private final ObjectMapper objectMapper = new ObjectMapper()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    @Value("${pbft.checkpoint.max-history:5}")
    private int checkpointHistoryLimit;

    @Value("${pbft.checkpoint.enabled:true}")
    private boolean checkpointingEnabled;

    private final ConcurrentMap<Long, PendingCheckpoint> pendingSnapshots = new ConcurrentHashMap<>();
    private final ConcurrentMap<Long, Map<String, ProofAccumulator>> proofBuckets = new ConcurrentHashMap<>();
    private final ConcurrentMap<Long, List<CheckpointProofMessage>> deferredProofs = new ConcurrentHashMap<>();
    private final AtomicLong highestPreparedCheckpoint = new AtomicLong(0);
    private final ConcurrentMap<Long, Object> checkpointLocks = new ConcurrentHashMap<>();

    @Transactional
    public void afterCommitMaybeCheckpoint(long seq) {
        try {
            if (!checkpointingEnabled) {
                log.debug("[{}] Checkpointing disabled → skipping seq={}", nodeState.getSelfNodeId(), seq);
                return;
            }
            int interval = Optional.ofNullable(nodeState.getClusterConfig())
                    .map(ClusterConfig::getCheckpointInterval)
                    .orElse(0);
            if (interval <= 0 || seq <= 0) {
                log.debug("[{}] Skip checkpoint trigger seq={} interval={}", nodeState.getSelfNodeId(), seq, interval);
                return;
            }
            if ((seq % interval) != 0) {
                log.debug("[{}] Skip checkpoint seq={} (interval={} remainder={})",
                        nodeState.getSelfNodeId(), seq, interval, seq % interval);
                return;
            }

            long lastCp = Math.max(nodeState.getLastCheckpointSequenceNumber(),
                    highestPreparedCheckpoint.get());
            if (seq <= lastCp) {
                log.debug("[{}] Skip checkpoint seq={} (lastCp={})", nodeState.getSelfNodeId(), seq, lastCp);
                return;
            }

            CheckpointService self = appContext.getBean(CheckpointService.class);

            Runnable trigger = () -> {
                // wait until executed ≥ seq
                while (nodeState.getLastExecutedSequenceNumber() < seq) {
                    try { Thread.sleep(50); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                }
                log.info("[{}] Triggering checkpoint build for seq={}", nodeState.getSelfNodeId(), seq);
                self.startCheckpoint(seq, "CHECKPOINT_SEQ_" + seq);
            };

            if (TransactionSynchronizationManager.isSynchronizationActive()) {
                TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                    @Override public void afterCommit() { trigger.run(); }
                });
            } else {
                trigger.run();
            }
        } catch (Exception e) {
            log.error("[{}] afterCommitMaybeCheckpoint failed: {}", nodeState.getSelfNodeId(), e.getMessage(), e);
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void startCheckpoint(long seq, String label) {
        if (!checkpointingEnabled) {
            log.debug("[{}] Checkpointing disabled → not starting seq={}", nodeState.getSelfNodeId(), seq);
            return;
        }
        Object lock = checkpointLocks.computeIfAbsent(seq, k -> new Object());
        synchronized (lock) {
            try {
                if (checkpointRepo.existsBySequenceNumber(seq)) {
                    log.debug("[{}] Checkpoint seq={} already persisted", nodeState.getSelfNodeId(), seq);
                    return;
                }
                if (pendingSnapshots.containsKey(seq)) {
                    log.debug("[{}] Checkpoint seq={} already pending", nodeState.getSelfNodeId(), seq);
                    return;
                }

                entityManager.flush();
                accountRepo.flush();
                Thread.sleep(150); // small stabilization window

                PendingCheckpoint pending = preparePendingCheckpoint(seq, label);
                if (pending == null) return;

                pendingSnapshots.put(seq, pending);
                dispatchProof(pending);

            } catch (Exception e) {
                log.error("[{}] Checkpoint start failed for seq {}: {}", nodeState.getSelfNodeId(), seq, e.getMessage(), e);
            } finally {
                checkpointLocks.remove(seq);
            }
        }
    }

    private PendingCheckpoint preparePendingCheckpoint(long seq, String label) throws Exception {
        return pendingSnapshots.computeIfAbsent(seq, k -> {
            try { return buildPendingCheckpoint(seq, label); }
            catch (Exception e) {
                log.error("buildPendingCheckpoint failed: {}", e.getMessage(), e);
                return null;
            }
        });
    }

    private PendingCheckpoint buildPendingCheckpoint(long seq, String label) throws Exception {
        entityManager.flush();
        accountRepo.flush();

        var accounts = accountRepo.findAll(Sort.by("name"));
        Map<String, Long> snapshot = accounts.stream()
                .collect(Collectors.toMap(
                        ClientAccountEntity::getName,
                        ClientAccountEntity::getBalance,
                        (a, b) -> a,
                        TreeMap::new));

        String json = objectMapper.writeValueAsString(snapshot);
        String digest = CryptoUtil.sha256Base64(json);

        PrivateKey priv = keyManager.selfPrivateKey();
        String signature = CryptoUtil.signBase64(seq + "|" + digest, priv);
        signature = byzantineService.maybeCorruptSignature(nodeState.getSelfNodeId(), signature);

        CheckpointSummary summary = CheckpointSummary.newBuilder()
                .setSequence(seq)
                .setLabel(label)
                .setDigest(digest)
                .build();

        CheckpointProof proof = CheckpointProof.newBuilder()
                .setReplicaId(nodeState.getSelfNodeId())
                .setSignature(signature)
                .build();

        log.info("[{}] Built checkpoint seq={} digest={} accounts={}",
                nodeState.getSelfNodeId(), seq, digest, snapshot.size());

        return new PendingCheckpoint(summary, json, proof);
    }


    private void dispatchProof(PendingCheckpoint pending) {
        if (!pending.markDispatched()) return;

        CheckpointProofMessage message = CheckpointProofMessage.newBuilder()
                .setSummary(pending.summary())
                .setProof(pending.proof())
                .build();

        long seq = pending.summary().getSequence();
        String dig = pending.summary().getDigest();

        String leaderId = nodeState.validPrimaryIdForView(nodeState.getCurrentView());
        if (leaderId == null || leaderId.isBlank()) {
            log.warn("[{}] No leader known; handling proof locally (seq={}, digest={})",
                    nodeState.getSelfNodeId(), seq, dig);
            handleCheckpointProofMessage(message);
            return;
        }

        if (leaderId.equals(nodeState.getSelfNodeId())) {
            handleCheckpointProofMessage(message);
        } else {
            nodeState.nodeInfo(leaderId).ifPresentOrElse(
                    meta -> {
                        log.info("[{}] Sending CHECKPOINT_PROOF(seq={},digest={}) → leader {}:{}",
                                nodeState.getSelfNodeId(), seq, dig, meta.getHost(), meta.getGrpcPort());
                        var ack = replicaClient.sendCheckpointProofToLeader(message, meta);
                        if (ack == null || !ack.getSuccess()) {
                            log.warn("[{}] Leader {} rejected/failed CHECKPOINT_PROOF seq={} digest={} → {}",
                                    nodeState.getSelfNodeId(), leaderId, seq, dig,
                                    ack == null ? "null ack" : ack.getMessage());
                        } else {
                            log.debug("[{}] Leader {} accepted CHECKPOINT_PROOF seq={} digest={}",
                                    nodeState.getSelfNodeId(), leaderId, seq, dig);
                        }
                    },
                    () -> {
                        log.warn("[{}] No leader metadata; handling locally (seq={})", nodeState.getSelfNodeId(), seq);
                        handleCheckpointProofMessage(message);
                    }
            );
        }
    }

    public synchronized void handleCheckpointProofMessage(CheckpointProofMessage message) {
        if (message == null || !message.hasSummary() || !message.hasProof()) return;

        CheckpointSummary summary = message.getSummary();
        CheckpointProof proof = message.getProof();

        long seq = summary.getSequence();
        String digest = summary.getDigest();

        long applied = nodeState.getLastExecutedSequenceNumber();
        if (applied < seq) {
            log.debug("[{}] Deferring checkpoint proof seq={} digest={} (applied={})",
                    nodeState.getSelfNodeId(), seq, digest, applied);
            deferredProofs.computeIfAbsent(seq, k -> Collections.synchronizedList(new ArrayList<>()))
                    .add(message);
            return;
        }

        PendingCheckpoint pending = pendingSnapshots.get(seq);
        if (pending == null) {
            CheckpointService self = appContext.getBean(CheckpointService.class);
            self.startCheckpoint(seq, summary.getLabel().isBlank() ? "CHECKPOINT_SEQ_" + seq : summary.getLabel());
            pending = pendingSnapshots.get(seq);
            if (pending == null) return;
        }

        if (!pending.summary().getDigest().equals(digest)) {
            log.warn("[{}] Digest mismatch at leader seq={} (have={}, incoming={})",
                    nodeState.getSelfNodeId(), seq, pending.summary().getDigest(), digest);
            try {
                PendingCheckpoint rebuilt = buildPendingCheckpoint(seq, pending.summary().getLabel());
                if (rebuilt != null && rebuilt.summary().getDigest().equals(digest)) {
                    pendingSnapshots.put(seq, rebuilt);
                    pending = rebuilt;
                    log.info("[{}] Rebuilt snapshot to adopt digest at seq={}", nodeState.getSelfNodeId(), seq);
                }
            } catch (Exception ex) {
                log.warn("[{}] Rebuild failed at seq {}: {}", nodeState.getSelfNodeId(), seq, ex.getMessage());
            }
        }

        if (!verifyProof(summary, proof)) {
            log.warn("[{}] Invalid checkpoint proof from {}", nodeState.getSelfNodeId(), proof.getReplicaId());
            return;
        }

        Map<String, ProofAccumulator> byDigest =
                proofBuckets.computeIfAbsent(seq, k -> new ConcurrentHashMap<>());
        ProofAccumulator acc =
                byDigest.computeIfAbsent(digest, d -> new ProofAccumulator());

        if (!acc.addProof(proof)) return;

        log.info("[{}] Checkpoint seq={} digest={} → collected proofs={}",
                nodeState.getSelfNodeId(), seq, digest, acc.size());

        if (acc.size() >= nodeState.quorumSize()) {
            List<CheckpointProof> proofs = new ArrayList<>(acc.proofs());
            proofs.sort(Comparator.comparing(CheckpointProof::getReplicaId));

            log.info("[{}] Forming checkpoint certificate seq={} digest={} proofs={}",
                    nodeState.getSelfNodeId(), seq, digest, proofs.size());

            CheckpointCertificate cert = CheckpointCertificate.newBuilder()
                    .setSequence(seq)
                    .setDigest(digest)
                    .addAllProofs(proofs)
                    .build();

            byDigest.remove(digest);
            if (byDigest.isEmpty()) proofBuckets.remove(seq);

            finalizeCheckpoint(summary, cert);
        }
    }

    private boolean verifyProof(CheckpointSummary summary, CheckpointProof proof) {
        try {
            String msg = summary.getSequence() + "|" + summary.getDigest();
            PublicKey pk = keyManager.publicKeyOf(proof.getReplicaId());
            return pk != null && CryptoUtil.verifyBase64(msg, proof.getSignature(), pk);
        } catch (Exception e) {
            return false;
        }
    }

    public synchronized void processDeferredProofs(long committedSeq) {
        List<Long> ready = deferredProofs.keySet().stream()
                .filter(seq -> seq <= committedSeq)
                .sorted()
                .toList();
        for (Long seq : ready) {
            List<CheckpointProofMessage> messages = deferredProofs.remove(seq);
            if (messages == null) continue;
            for (CheckpointProofMessage msg : messages) handleCheckpointProofMessage(msg);
        }
    }

    private boolean verifyCertificate(CheckpointCertificate cert) {
        try {
            String msg = cert.getSequence() + "|" + cert.getDigest();
            long valid = cert.getProofsList().stream().filter(p -> {
                try {
                    PublicKey pk = keyManager.publicKeyOf(p.getReplicaId());
                    return pk != null && CryptoUtil.verifyBase64(msg, p.getSignature(), pk);
                } catch (Exception ex) {
                    return false;
                }
            }).count();
            return valid >= nodeState.quorumSize();
        } catch (Exception e) {
            return false;
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    protected void persistStableCheckpoint(CheckpointSummary summary, CheckpointCertificate certificate) throws Exception {
        String selfId = nodeState.getSelfNodeId();
        boolean crashed = byzantineService != null && byzantineService.isCrashed(selfId);
        if (!nodeState.isParticipating() || crashed) {
            log.info("[{}] Skipping checkpoint seq={} (spectator/crash mode)", nodeState.getSelfNodeId(), summary.getSequence());
            return;
        }

        long seq = summary.getSequence();
        String label = summary.getLabel().isBlank() ? "CHECKPOINT_SEQ_" + seq : summary.getLabel();
        String digest = summary.getDigest();

        String state = resolveSerializedState(seq, digest, certificate, summary);
        if (state == null || state.isBlank()) {
            throw new IllegalStateException("Missing snapshot seq=" + seq);
        }

        String certJson = JsonFormat.printer()
                .includingDefaultValueFields()
                .omittingInsignificantWhitespace()
                .print(certificate);
        String certDigest = CryptoUtil.sha256Base64(certJson);

        CheckpointEntity entity = checkpointRepo.findBySequenceNumber(seq).orElseGet(CheckpointEntity::new);
        entity.setSequenceNumber(seq);
        entity.setLabel(label);
        entity.setDigest(digest);
        entity.setSerializedState(state);
        entity.setCertificateJson(certJson);
        entity.setCertificateDigest(certDigest);
        entity.setProofCount(certificate.getProofsCount());
        checkpointRepo.saveAndFlush(entity);

        pendingSnapshots.remove(seq);
        proofBuckets.remove(seq);
        highestPreparedCheckpoint.updateAndGet(prev -> Math.max(prev, seq));
        nodeState.markCheckpointSequenceNumber((int) seq);
        nodeState.setLastCheckpointLabel(label);
        replicaLogEntry.markCheckpoint(label, seq);

        pruneOldCheckpoints();

        log.info("[{}] Persisted checkpoint seq={} digest={} proofs={}",
                nodeState.getSelfNodeId(), seq, digest, certificate.getProofsCount());
    }

    private void finalizeCheckpoint(CheckpointSummary summary, CheckpointCertificate certificate) {
        if (certificate == null || summary == null) return;
        if (!summary.getDigest().equals(certificate.getDigest())) return;
        if (!verifyCertificate(certificate)) return;

        try {
            persistStableCheckpoint(summary, certificate);
        } catch (Exception e) {
            log.error("Persist failed: {}", e.getMessage(), e);
            return;
        }

        if (nodeState.isPrimary()) {
            var targets = nodeState.livePeersExcludingSelf();
            if (!targets.isEmpty()) {
                CheckpointCertificateBroadcast payload = CheckpointCertificateBroadcast.newBuilder()
                        .setSummary(summary)
                        .setCertificate(certificate)
                        .build();
                replicaClient.broadcastCheckpointCertificate(payload, targets);
            }
        }
    }

    public void handleCheckpointCertificateBroadcast(CheckpointCertificateBroadcast broadcast) {
        try {
            if (broadcast == null || !broadcast.hasSummary() || !broadcast.hasCertificate()) return;
            if (!verifyCertificate(broadcast.getCertificate())) {
                log.warn("[{}] Invalid checkpoint certificate seq={}", nodeState.getSelfNodeId(),
                        broadcast.getSummary().getSequence());
                return;
            }
            persistStableCheckpoint(broadcast.getSummary(), broadcast.getCertificate());
            log.info("[{}] Applied checkpoint certificate seq={} digest={}",
                    nodeState.getSelfNodeId(),
                    broadcast.getSummary().getSequence(),
                    broadcast.getSummary().getDigest());
        } catch (Exception e) {
            log.error("handleCheckpointCertificateBroadcast error: {}", e.getMessage(), e);
        }
    }

    public Optional<CheckpointSummary> loadLatestCheckpointSummary() {
        long committedFloor = Math.max(
                nodeState.getLastExecutedSequenceNumber(),
                nodeState.getLastCommitSequenceNumber());
        try {
            Optional<CheckpointSummary> stored = checkpointRepo.findTopByOrderBySequenceNumberDesc()
                    .filter(cp -> cp.getSequenceNumber() <= committedFloor)
                    .map(cp -> CheckpointSummary.newBuilder()
                            .setSequence(cp.getSequenceNumber())
                            .setDigest(Optional.ofNullable(cp.getDigest()).orElse(""))
                            .setLabel(Optional.ofNullable(cp.getLabel()).orElse(""))
                            .build());
            if (stored.isPresent()) {
                return stored;
            }
        } catch (Exception e) {
            log.warn("[{}] Failed to load stored checkpoint summary: {}", nodeState.getSelfNodeId(), e.getMessage());
        }

        return pendingSnapshots.entrySet().stream()
                .map(Map.Entry::getValue)
                .filter(Objects::nonNull)
                .filter(pc -> pc.sequence() <= committedFloor)
                .max(Comparator.comparingLong(PendingCheckpoint::sequence))
                .map(pc -> CheckpointSummary.newBuilder(pc.summary()).build());
    }

    /* ------------------------------------------------------------- */
    /* Fetch (for PbftService.getCheckpointState)                    */
    /* ------------------------------------------------------------- */

    public CheckpointState serveCheckpointState(long seq, String digest, String requester) {
        return checkpointRepo.findBySequenceNumber(seq)
                .map(cp -> CheckpointState.newBuilder()
                        .setSequence(cp.getSequenceNumber())
                        .setDigest(cp.getDigest())
                        .setSerializedStateJson(cp.getSerializedState())
                        .build())
                .orElse(CheckpointState.newBuilder()
                        .setSequence(seq)
                        .setDigest(digest == null ? "" : digest)
                        .setSerializedStateJson("")
                        .build());
    }

    public void restoreLatestCheckpoint() {
        checkpointRepo.findTopByOrderBySequenceNumberDesc().ifPresentOrElse(cp -> {
            try {
                Map<String, Long> balances = objectMapper.readValue(
                        cp.getSerializedState(),
                        new TypeReference<Map<String, Long>>() {});
                for (var e : balances.entrySet()) accountRepo.updateBalance(e.getKey(), e.getValue());
                nodeState.markCheckpointSequenceNumber((int) cp.getSequenceNumber());
                highestPreparedCheckpoint.updateAndGet(prev -> Math.max(prev, cp.getSequenceNumber()));
                log.info("[Checkpoint] Restored seq={} digest={}", cp.getSequenceNumber(), cp.getDigest());
            } catch (Exception e) {
                log.error("Restore failed: {}", e.getMessage(), e);
            }
        }, () -> log.warn("No checkpoints found to restore."));
    }


    private static final class PendingCheckpoint {
        private final CheckpointSummary summary;
        private final String serializedState;
        private final CheckpointProof proof;
        private final AtomicBoolean dispatched = new AtomicBoolean(false);

        PendingCheckpoint(CheckpointSummary s, String json, CheckpointProof p) {
            this.summary = s; this.serializedState = json; this.proof = p;
        }
        CheckpointSummary summary() { return summary; }
        CheckpointProof proof() { return proof; }
        String serializedState() { return serializedState; }
        long sequence() { return summary.getSequence(); }
        boolean markDispatched() { return dispatched.compareAndSet(false, true); }
    }

    private static final class ProofAccumulator {
        private final ConcurrentMap<String, CheckpointProof> proofs = new ConcurrentHashMap<>();
        boolean addProof(CheckpointProof p) { return proofs.putIfAbsent(p.getReplicaId(), p) == null; }
        int size() { return proofs.size(); }
        Collection<CheckpointProof> proofs() { return proofs.values(); }
    }


    /** Used by ViewChangePhaseHandlerImpl */
    public Optional<CheckpointCertificate> loadBestValidCertificate() {
        long committedFloor = Math.max(
                nodeState.getLastExecutedSequenceNumber(),
                nodeState.getLastCommitSequenceNumber());

        return checkpointRepo.findTopByOrderBySequenceNumberDesc()
                .filter(cp -> {
                    boolean usable = cp.getSequenceNumber() <= committedFloor;
                    if (!usable) {
                    }
                    return usable;
                })
                .flatMap(cp -> {
                    try {
                        var builder = CheckpointCertificate.newBuilder();
                        JsonFormat.parser().merge(cp.getCertificateJson(), builder);
                        CheckpointCertificate cert = builder.build();
                        if (verifyCertificate(cert)) return Optional.of(cert);
                    } catch (Exception e) {
                    }
                    return Optional.empty();
                });
    }

    public void createCheckpoint(int seq) {
        afterCommitMaybeCheckpoint(seq);
    }

    public void clearAll() {
        pendingSnapshots.clear();
        proofBuckets.clear();
        deferredProofs.clear();
        checkpointLocks.clear();
        highestPreparedCheckpoint.set(0);

        try {
            entityManager.createNativeQuery("DELETE FROM checkpoint").executeUpdate();
            entityManager.createNativeQuery("ALTER TABLE checkpoint AUTO_INCREMENT = 1").executeUpdate();
        } catch (Exception e) {
        }
    }

    public DebugSnapshot debugSnapshot() {
        Map<Long, String> pending = pendingSnapshots.values().stream()
                .collect(Collectors.toMap(PendingCheckpoint::sequence, p -> p.summary().getDigest(), (a, b) -> b));

        Map<Long, Map<String, Integer>> counts = new HashMap<>();
        proofBuckets.forEach((seq, byDigest) -> {
            Map<String, Integer> inner = new HashMap<>();
            byDigest.forEach((dig, acc) -> inner.put(dig, acc.size()));
            counts.put(seq, inner);
        });

        Map<Long, Integer> deferredCounts = deferredProofs.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue() == null ? 0 : e.getValue().size()));

        Optional<CheckpointSummary> latest = loadLatestCheckpointSummary();

        return new DebugSnapshot(pending, counts, deferredCounts, highestPreparedCheckpoint.get(), latest.orElse(null));
    }

    private void pruneOldCheckpoints() {
        if (checkpointHistoryLimit <= 0) return;
        try {
            var keep = checkpointRepo.findAllByOrderBySequenceNumberDesc(PageRequest.of(0, checkpointHistoryLimit));
            if (keep.isEmpty()) {
                return;
            }
            long minSeqToKeep = keep.get(keep.size() - 1).getSequenceNumber();
            checkpointRepo.deleteOlderThan(minSeqToKeep);
        } catch (Exception e) {
            log.warn("[{}] Failed pruning old checkpoints: {}", nodeState.getSelfNodeId(), e.getMessage());
        }
    }

    public record DebugSnapshot(Map<Long, String> pendingDigests,
                                Map<Long, Map<String, Integer>> proofBuckets,
                                Map<Long, Integer> deferredProofs,
                                long highestPreparedSequence,
                                CheckpointSummary latestSummary) {}

    private String resolveSerializedState(long seq,
                                          String expectedDigest,
                                          CheckpointCertificate certificate,
                                          CheckpointSummary summary) {
        PendingCheckpoint pending = pendingSnapshots.get(seq);
        if (pending != null) {
            return pending.serializedState();
        }

        Optional<CheckpointEntity> existing = checkpointRepo.findBySequenceNumber(seq);
        if (existing.isPresent()) {
            String serialized = existing.get().getSerializedState();
            if (serialized != null && !serialized.isBlank()) {
                if (digestMatches(serialized, expectedDigest)) {
                    return serialized;
                }
                log.warn("[{}] Stored checkpoint seq={} digest mismatch (stored vs summary)", nodeState.getSelfNodeId(), seq);
            }
        }

        String digest = expectedDigest;
        if ((digest == null || digest.isBlank()) && certificate != null) {
            digest = certificate.getDigest();
        }
        if (digest == null || digest.isBlank()) {
            return null;
        }

        String selfId = nodeState.getSelfNodeId();
        boolean crashed = byzantineService != null && byzantineService.isCrashed(selfId);
        if (!nodeState.isParticipating() || crashed) {
            return null;
        }

        String fetched = fetchSerializedStateFromPeers(seq, digest, certificate, summary);
        if (fetched != null && digestMatches(fetched, digest)) {
            return fetched;
        }
        return null;
    }

    private boolean digestMatches(String serialized, String expectedDigest) {
        if (expectedDigest == null || expectedDigest.isBlank()) return true;
        try {
            String actual = CryptoUtil.sha256Base64(serialized);
            return expectedDigest.equals(actual);
        } catch (Exception e) {
            return false;
        }
    }

    private String fetchSerializedStateFromPeers(long seq,
                                                 String digest,
                                                 CheckpointCertificate certificate,
                                                 CheckpointSummary summary) {
        Set<String> candidateIds = new LinkedHashSet<>();
        if (certificate != null) {
            certificate.getProofsList().stream()
                    .map(CheckpointProof::getReplicaId)
                    .filter(id -> id != null && !id.isBlank())
                    .forEach(candidateIds::add);
        }

        candidateIds.remove(nodeState.getSelfNodeId());
        nodeState.livePeersExcludingSelf().forEach(meta -> candidateIds.add("node-" + meta.getId()));

        for (String replicaId : candidateIds) {
            if (replicaId == null || replicaId.isBlank()) continue;
            Optional<ClusterConfig.NodeMetaData> metaOpt = nodeState.nodeInfo(replicaId);
            if (metaOpt.isEmpty()) continue;
            ClusterConfig.NodeMetaData meta = metaOpt.get();
            Optional<CheckpointState> stateOpt = replicaClient.fetchCheckpointState(seq, digest, meta);
            if (stateOpt.isEmpty()) continue;

            String serialized = stateOpt.get().getSerializedStateJson();
            if (serialized == null || serialized.isBlank()) continue;

            if (!digestMatches(serialized, digest)) {
                continue;
            }

            return serialized;
        }


        return null;
    }

}
