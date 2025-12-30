package com.distributedsystems.pbft.util.CSVHandler;

import com.distributedsystems.pbft.client.ReplicaClient;
import com.distributedsystems.pbft.model.ReadLogEntity;
import com.distributedsystems.pbft.proto.ClientReply;
import com.distributedsystems.pbft.proto.PbftServiceGrpc;
import com.distributedsystems.pbft.repository.IClientAccountRepository;
import com.distributedsystems.pbft.repository.IReplicatLogRepository;
import com.distributedsystems.pbft.repository.IReadLogRepository;
import com.distributedsystems.pbft.service.ByzantineService;
import com.distributedsystems.pbft.service.CheckpointService;
import com.distributedsystems.pbft.service.ExecutionServiceImpl;
import com.distributedsystems.pbft.service.PbftTimerService;
import com.distributedsystems.pbft.service.PrimaryImplementation;
import com.distributedsystems.pbft.service.PhaseHandlers.CommitPhaseHandlerImpl;
import com.distributedsystems.pbft.state.NodeState;
import com.distributedsystems.pbft.service.PhaseHandlers.PrePreparePhaseHandlerImpl;
import com.distributedsystems.pbft.service.PhaseHandlers.ViewChangePhaseHandlerImpl;
import com.distributedsystems.pbft.service.ThresholdSignatureService;
import com.google.protobuf.Empty;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class CSVScenarioConcurrentService {

    private final NodeState nodeState;
    private final ReplicaClient replicaClient;
    private final IClientAccountRepository accountRepo;
    private final IReplicatLogRepository replicaLogRepository;
    private final CheckpointService checkpointService;
    private final ExecutionServiceImpl executionService;
    private final PbftTimerService pbftTimerService;
    private final CommitPhaseHandlerImpl commitPhaseHandler;
    private final ViewChangePhaseHandlerImpl viewChangeHandler;
    private final PrePreparePhaseHandlerImpl prePreparePhaseHandler;
    private final PrimaryImplementation primaryImplementation;
    private final ThresholdSignatureService thresholdSignatureService;
    private final PlatformTransactionManager transactionManager;
    @Autowired
    private ByzantineService byzantineService;

    @PersistenceContext
    private EntityManager em;

    private final Queue<String> retryBuffer = new ConcurrentLinkedQueue<>();
    private static final int IN_SET_RETRY_LIMIT = 2;
    private static final Duration IN_SET_RETRY_DELAY = Duration.ofSeconds(4);
    private static final Object INPUT_LOCK = new Object();
    private static final BufferedReader STDIN =
            (System.console() == null) ? new BufferedReader(new InputStreamReader(System.in)) : null;

    private static final Duration CLIENT_TIMEOUT      = Duration.ofSeconds(5);
    private static final Duration CLIENT_RETRY_EVERY  = Duration.ofSeconds(3);
    private static final Duration CLIENT_MAX_WAIT     = Duration.ofSeconds(10);
    private static final Duration CLIENT_MAX_WAIT_SLOW = Duration.ofSeconds(40);
    private static final Duration SET_MAX_WAIT        = Duration.ofSeconds(18);
    private static final Pattern CSV_SAFE_SPLIT = Pattern.compile(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
    private static final Pattern N_PATTERN = Pattern.compile("[nN](\\d+)");
    private static final Pattern DARK_PATTERN = Pattern.compile("(?i)dark\\s*\\(([^)]*)\\)");
    private static final Pattern EQUIV_PATTERN = Pattern.compile("(?i)equivocat(?:e|ion)\\s*\\(([^)]*)\\)");
    private static final Set<String> FAST_PATH_BLOCKERS = Set.of("crash", "dark", "partition", "delay");
    private enum FlushKind { FULL, SOFT }

    private volatile Duration activeClientMaxWait = CLIENT_MAX_WAIT;
    private volatile boolean fatalAttackActive = false;
    private volatile int currentHonestNodes = 0;
    private final IReadLogRepository readLogRepository;
    @Value("${pbft.clients.concurrent-request-processing:false}")
    private boolean concurrentClientRequests;

    public String runCsvScenarioConcurrent(String csvPath, int ignoredClients) {
        log.warn("CSV Runner using file: {}", csvPath);

        final String self = nodeState.getSelfNodeId();
        final int clients = (ignoredClients > 0) ? ignoredClients : 10;
        log.info("[{}] Running CSV scenario from {} with {} clients (concurrentRequestsEnabled={})",
                self, csvPath, clients, concurrentClientRequests);

        try (Reader in = Files.newBufferedReader(Paths.get(csvPath), StandardCharsets.UTF_8)) {
            Iterable<CSVRecord> it = CSVFormat.DEFAULT
                    .withFirstRecordAsHeader()
                    .withIgnoreHeaderCase()
                    .withTrim(true)
                    .withAllowMissingColumnNames()
                    .parse(in);

            List<ScenarioSet> sets = parseSets(it);

            List<String> clientIds = new ArrayList<>(clients);
            for (int i = 1; i <= clients; i++) clientIds.add("client-" + i);

            for (int i = 0; i < sets.size(); i++) {
                ScenarioSet set = sets.get(i);
                boolean fatalThisSet = false;
                boolean fatalViewChangeRequested = false;

                if (pbftTimerService != null) {
                    pbftTimerService.pauseTimers("CSV Set " + set.label() + " awaiting start");
                    nodeState.setParticipating(false);
                    replicaClient.broadcastTimerControl(true, "CSV awaiting start " + set.label());
                }

                System.err.println();
                System.err.println("Ready to execute SET " + set.label());
                System.err.println("Live: " + (set.liveRaw().isBlank() ? "(not specified)" : set.liveRaw()));
                if (!set.byzRaw().isBlank())    System.err.println("Byzantine: " + set.byzRaw());
                if (!set.attackRaw().isBlank()) System.err.println("Attack:    " + set.attackRaw());
                System.err.println("Txns: " + (set.transactions().isEmpty() ? "(none)" : set.transactions()));
                System.err.println("Press ENTER to START this set...");
                waitForEnter();

                Duration settleWait = (i == 0) ? Duration.ZERO : Duration.ofSeconds(3);
                if (!settleWait.isZero()) {
                    waitForQuiescence(settleWait, Duration.ofMillis(250));
                }
                log.warn("[{}] Performing FULL flush before starting SET {}...", self, set.label());
                broadcastAdminFlush(FlushKind.FULL);

                logLocalBalances("Set " + set.label() + " start");

                applyLiveSet(set.liveRaw(), set.byzRaw(), set.attackRaw());
                fatalThisSet = fatalAttackActive;
                if (fatalThisSet && !fatalViewChangeRequested) {
                    requestFatalViewChange("CSV set " + set.label() + " detected fatal attack");
                    fatalViewChangeRequested = true;
                }

                List<String> tokens = new ArrayList<>(set.transactions());
                if (!retryBuffer.isEmpty()) {
                    List<String> carry = new ArrayList<>(retryBuffer);
                    retryBuffer.clear();
                    carry.addAll(tokens);
                    tokens = carry;
                    log.warn("[{}] Replaying {} deferred tx(s) at the beginning of this set.", self, carry.size());
                }


                if (pbftTimerService != null) {
                    pbftTimerService.armTimers("CSV Set " + set.label() + " executing");
                    nodeState.setParticipating(true);
                    replicaClient.broadcastTimerControl(false, "CSV executing set " + set.label());
                }
                if (fatalThisSet) {
                    log.warn("[{}] Skipping execution of SET {} (fatal attack prevents quorum).",
                            self, set.label());
                    if (!tokens.isEmpty()) {
                        retryBuffer.addAll(tokens);
                        log.warn("[{}] Deferred {} token(s) for retry on a future set.", self, tokens.size());
                    }
                    continue;
                }

                List<TransferPlanEntry> transferPlan = buildTransferPlan(set, tokens);
                List<TransferPlanEntry> failed = concurrentClientRequests
                        ? runTokensConcurrent(set, tokens, transferPlan.iterator(), clientIds)
                        : runTokensSerial(set, tokens, transferPlan.iterator(), transferPlan.size(), fatalThisSet);
                int inlineRetries = 0;
                while (!failed.isEmpty()
                        && !fatalThisSet
                        && hasHonestQuorum()
                        && inlineRetries < IN_SET_RETRY_LIMIT) {
                    inlineRetries++;
                    log.warn("[{}] SET {} retry {}/{}: {} tx(s) timed out but honest quorum {} ≥ {} — "
                                    + "waiting {}s for view-change stabilization.",
                            self, set.label(), inlineRetries, IN_SET_RETRY_LIMIT,
                            failed.size(), currentHonestNodes, nodeState.quorumSize(),
                            IN_SET_RETRY_DELAY.getSeconds());
                    waitForQuiescence(IN_SET_RETRY_DELAY, Duration.ofMillis(250));
                    failed = rerunFailedTransfers(new ArrayList<>(failed));
                }

                if (!failed.isEmpty()) {
                    log.warn("[{}] SET {} had {} uncommitted tx(s) → will retry on next set.",
                            self, set.label(), failed.size());
                    if (failed.size() == transferPlan.size() && !transferPlan.isEmpty()) {
                        System.err.println();
                        System.err.println("Set " + set.label() + ": no majority quorum achieved — exiting this set.");
                    }
                }

                if (fatalThisSet && failed.size() == transferPlan.size() && !transferPlan.isEmpty()) {
                    System.err.println();
                    System.err.println("Set " + set.label() + ": fatal attack prevented quorum — moving on after view-change exhaustion.");
                }

                log.info("Completed SET {}", set.label());

                if (pbftTimerService != null) {
                    pbftTimerService.pauseTimers("CSV Set " + set.label() + " completed");
                    nodeState.setParticipating(false);
                    replicaClient.broadcastTimerControl(true, "CSV set completed " + set.label());
                }

                try {
                    checkpointService.createCheckpoint(set.index());
                    logLocalBalances("Set " + set.label() + " completed (no checkpoint flush)");

                } catch (Exception e) {
                    log.warn("Failed to create checkpoint for set {}: {}", set.label(), e.getMessage());
                }
            }

            log.info("All sets completed.");
            return "CSV concurrent scenario completed successfully.";

        } catch (Exception e) {
            log.error("[{}] CSV concurrent error: {}", self, e.toString(), e);
            return "Error running scenario: " + e.getMessage();
        } finally {
            if (pbftTimerService != null) {
                pbftTimerService.pauseTimers("CSV scenario idle");
                replicaClient.broadcastTimerControl(true, "CSV scenario idle");
            }
        }
    }

    private List<TransferPlanEntry> runTokensConcurrent(ScenarioSet set,
                                                        List<String> tokens,
                                                        Iterator<TransferPlanEntry> transferPlan,
                                                        List<String> clientIds) throws InterruptedException {
        if (tokens == null || tokens.isEmpty()) return List.of();
        if (clientIds == null || clientIds.isEmpty()) return List.of();

        List<TransferPlanEntry> failed = Collections.synchronizedList(new ArrayList<>());
        Map<String, ClientContext> clientContexts = new LinkedHashMap<>();
        for (String clientId : clientIds) {
            clientContexts.put(clientId, new ClientContext(clientId, failed));
        }

        List<CompletableFuture<Void>> completions = new ArrayList<>();
        AtomicInteger rr = new AtomicInteger(0);
        final String setLabel = set.label();

        for (String raw : tokens) {
            final String tx = (raw == null) ? "" : raw.trim();
            if (tx.isEmpty()) continue;

            String normalized = tx.replace("(", "").replace(")", "").trim();
            String[] parts = normalized.split(",");
            if (parts.length == 1) {
                showBalance(setLabel, normalized);
                continue;
            }

            if (parts.length != 3) {
                log.warn("Skipping malformed tx: {}", tx);
                continue;
            }

            if (!transferPlan.hasNext()) {
                log.error("[{}] Transfer plan exhausted early for set {} at '{}'",
                        nodeState.getSelfNodeId(), setLabel, tx);
                break;
            }

            final TransferPlanEntry base = transferPlan.next();
            final String assignedClient = clientIds.get(Math.floorMod(rr.getAndIncrement(), clientIds.size()));
            final TransferPlanEntry spec = new TransferPlanEntry(
                    base.raw(), base.from(), base.to(), base.amount(),
                    assignedClient, base.ordinal(), base.timestamp());

            ClientContext context = clientContexts.get(assignedClient);
            if (context == null) continue;
            completions.add(context.submit(new TransferCommand(spec)));
        }

        try {
            CompletableFuture<Void> all = CompletableFuture.allOf(completions.toArray(new CompletableFuture[0]));
            try {
                all.get(Math.max(SET_MAX_WAIT.toMillis(), 10000L), TimeUnit.MILLISECONDS);
            } catch (TimeoutException te) {
                log.warn("[{}] Set '{}' timed out waiting for clients → proceeding",
                        nodeState.getSelfNodeId(), setLabel);
            }
            Thread.sleep(2000);
        } catch (Exception e) {
            log.warn("[{}] runTokensConcurrent join failed: {}", nodeState.getSelfNodeId(), e.getMessage());
        } finally {
            clientContexts.values().forEach(ClientContext::shutdown);
        }

        return new ArrayList<>(failed);
    }

    private List<TransferPlanEntry> runTokensSerial(ScenarioSet set,
                                                    List<String> tokens,
                                                    Iterator<TransferPlanEntry> transferPlan,
                                                    int totalTransfers,
                                                    boolean abortOnTimeout) throws InterruptedException {
        if (tokens == null || tokens.isEmpty()) return List.of();

        List<TransferPlanEntry> failed = new ArrayList<>();
        long lastCommittedSeqSeen = 0L;
        boolean abortedByTimeout = false;
        boolean abortedByMissingQuorum = false;
        final int liveCountSnapshot = safeLiveCount();
        final int honestSnapshot = Math.max(0, currentHonestNodes);
        final int quorumSize = nodeState.quorumSize();
        final boolean majorityImpossible = honestSnapshot < quorumSize;
        final String setLabel = set.label();
        int processedTransfers = 0;

        for (int idx = 0; idx < tokens.size(); idx++) {
            String raw = tokens.get(idx);
            final String tx = (raw == null) ? "" : raw.trim();
            if (tx.isEmpty()) continue;

            String normalized = tx.replace("(", "").replace(")", "").trim();
            String[] parts = normalized.split(",");
            if (parts.length == 1) {
                waitLocalExecAtLeast(lastCommittedSeqSeen, Duration.ofSeconds(3), Duration.ofMillis(100));
                showBalance(setLabel, normalized);
                continue;
            }

            if (parts.length != 3) {
                log.warn("Skipping malformed tx: {}", tx);
                continue;
            }

            processedTransfers++;
            final TransferPlanEntry spec;
            if (transferPlan.hasNext()) {
                spec = transferPlan.next();
            } else {
                log.error("[{}] Transfer plan exhausted early for set {} at '{}'", nodeState.getSelfNodeId(), setLabel, tx);
                break;
            }

            try {
                ClientReply finalReply = replicaClient.submitUntilExecuted(
                        spec.from(), spec.to(), spec.amount(), spec.clientId(), spec.timestamp(),
                        CLIENT_TIMEOUT, CLIENT_RETRY_EVERY, activeClientMaxWait);

                if (!isFinalOk(finalReply)) {
                    log.error("[{}] No success before max wait → deferring {}", spec.clientId(), spec.raw());
                    failed.add(spec);

                    boolean timeoutReply = isLocalTimeout(finalReply);
                    boolean shouldAbort = false;
                    boolean abortDueToQuorum = false;
                    if (timeoutReply) {
                        if (abortOnTimeout) {
                            shouldAbort = true;
                        } else if (majorityImpossible) {
                            shouldAbort = true;
                            abortDueToQuorum = true;
                        }
                    }

                    if (shouldAbort) {
                        if (abortDueToQuorum) {
                            abortedByMissingQuorum = true;
                        } else if (abortOnTimeout) {
                            abortedByTimeout = true;
                        }
                        int remaining = Math.max(0, totalTransfers - processedTransfers);
                        if (abortDueToQuorum) {
                            log.warn("[{}] Honest roster {} (live {}) < quorum {} after '{}' → aborting remaining {} operation(s) in set {}",
                                    nodeState.getSelfNodeId(), honestSnapshot, liveCountSnapshot,
                                    quorumSize, tx, remaining, setLabel);
                        } else {
                            log.warn("[{}] Max wait reached under fatal attack for '{}' → aborting remaining {} operation(s) in set {}",
                                    spec.clientId(), tx, remaining, setLabel);
                        }
                        while (transferPlan.hasNext()) {
                            failed.add(transferPlan.next());
                        }
                        break;
                    }
                } else {
                    log.info("[{}] Completed successfully: {}", spec.clientId(), spec.raw());
                    long seq = finalReply.getSequence();
                    if (seq > 0) lastCommittedSeqSeen = Math.max(lastCommittedSeqSeen, seq);
                }
            } catch (Exception e) {
                log.error("[{}] {} failed: {}", spec.clientId(), spec.raw(), e.getMessage());
                failed.add(spec);
            }
        }

        if (abortedByTimeout) {
            log.warn("[{}] Set {} aborted after local client timeout; {} operation(s) marked failed.",
                    nodeState.getSelfNodeId(), setLabel, failed.size());
        }

        if (abortedByMissingQuorum) {
            log.warn("[{}] Set {} aborted after detecting honest roster {} (live {}) < quorum {}; {} operation(s) marked failed.",
                    nodeState.getSelfNodeId(), setLabel, honestSnapshot, liveCountSnapshot, quorumSize, failed.size());
        }

        return failed;
    }

    private List<TransferPlanEntry> buildTransferPlan(ScenarioSet set, List<String> tokens) {
        List<TransferPlanEntry> plan = new ArrayList<>();
        if (set == null || tokens == null || tokens.isEmpty()) {
            return plan;
        }

        DeterministicTimestampSequencer sequencer = new DeterministicTimestampSequencer(set.index());
        String clientId = "csv-" + set.label() + "-seq";
        for (String raw : tokens) {
            String tx = (raw == null) ? "" : raw.trim();
            if (tx.isEmpty()) continue;

            String normalized = tx.replace("(", "").replace(")", "").trim();
            String[] parts = normalized.split(",");
            if (parts.length != 3) continue;

            String from = parts[0].trim();
            String to = parts[1].trim();
            long amount = Long.parseLong(parts[2].trim());
            plan.add(sequencer.next(tx, from, to, amount, clientId));
        }
        return plan;
    }

    private List<TransferPlanEntry> rerunFailedTransfers(List<TransferPlanEntry> candidates) {
        if (candidates == null || candidates.isEmpty()) return List.of();

        List<TransferPlanEntry> ordered = new ArrayList<>(candidates);
        ordered.sort(Comparator.comparingInt(TransferPlanEntry::ordinal));

        List<TransferPlanEntry> failedAgain = new ArrayList<>();
        for (TransferPlanEntry spec : ordered) {
            try {
                ClientReply finalReply = replicaClient.submitUntilExecuted(
                        spec.from(), spec.to(), spec.amount(), spec.clientId(), spec.timestamp(),
                        CLIENT_TIMEOUT, CLIENT_RETRY_EVERY, activeClientMaxWait);

                if (!isFinalOk(finalReply)) {
                    log.error("[{}] No success before max wait → deferring {}", spec.clientId(), spec.raw());
                    failedAgain.add(spec);
                } else {
                    log.info("[{}] Completed successfully: {}", spec.clientId(), spec.raw());
                }
            } catch (Exception e) {
                log.error("[{}] {} failed: {}", spec.clientId(), spec.raw(), e.getMessage());
                failedAgain.add(spec);
            }
        }
        return failedAgain;
    }

    private int safeLiveCount() {
        try {
            Set<Integer> lives = nodeState.getLiveNodes();
            return (lives == null) ? 0 : lives.size();
        } catch (Exception e) {
            log.warn("Failed to read live roster size: {}", e.getMessage());
            return 0;
        }
    }
    
    private boolean hasHonestQuorum() {
        return currentHonestNodes >= nodeState.quorumSize();
    }

    private boolean isLocalTimeout(ClientReply reply) {
        if (reply == null) return false;
        if (reply.getSequence() != 0L) return false;
        if (!"FAIL".equalsIgnoreCase(reply.getResult())) return false;
        String replicaId = reply.getReplicaId();
        return replicaId != null && replicaId.equals(nodeState.getSelfNodeId());
    }

    private boolean looksLikeTransfer(String token) {
        String normalized = token.replace("(", "").replace(")", "").trim();
        String[] parts = normalized.split(",");
        return parts.length == 3;
    }

    private void waitLocalExecAtLeast(long minSeq, Duration timeout, Duration pollEvery) {
        if (minSeq <= 0) return;
        long start = System.currentTimeMillis();
        long maxWaitMs = (timeout == null) ? 0L : timeout.toMillis();
        long pollMs = (pollEvery == null) ? 100L : pollEvery.toMillis();
        while (true) {
            try { Thread.sleep(pollMs); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); return; }
            long cur = nodeState.getLastExecutedSequenceNumber();
            if (cur >= minSeq) return;
            if (maxWaitMs > 0 && (System.currentTimeMillis() - start) >= maxWaitMs) return;
        }
    }

    private void showBalance(String setLabel, String accountName) {
        String name = accountName.trim();
        if (name.isEmpty()) return;
        long balance = fetchAuthoritativeBalance(setLabel, name);
        log.info("[Set {}] BALANCE({}) = {}", setLabel, name, balance);
        recordBalanceRead(setLabel, name, balance);
    }

    private void recordBalanceRead(String setLabel, String account, long balance) {
        if (readLogRepository == null) return;
        try {
            String payload = String.format(
                    "{\"set\":\"%s\",\"operation\":\"BALANCE\",\"account\":\"%s\",\"response\":\"%s\"}",
                    setLabel == null ? "" : setLabel,
                    account == null ? "" : account,
                    "BALANCE=" + balance);
            ReadLogEntity entry = ReadLogEntity.builder()
                    .source(setLabel == null ? "" : setLabel)
                    .account(account == null ? "" : account)
                    .payload(payload)
                    .result("BALANCE=" + balance)
                    .recordedAt(Instant.now())
                    .build();
            readLogRepository.save(entry);
        } catch (Exception e) {
            log.warn("[{}] Failed to record BALANCE({}) read: {}", nodeState.getSelfNodeId(), account, e.getMessage());
        }
    }

    private void requestFatalViewChange(String reason) {
        if (viewChangeHandler == null) {
            log.warn("[{}] Cannot request view-change for fatal attack (handler unavailable)", nodeState.getSelfNodeId());
            return;
        }
        String label = (reason == null || reason.isBlank())
                ? "CSV fatal attack (honest roster < quorum)"
                : reason;
        try {
            log.warn("[{}] Requesting proactive view-change: {}", nodeState.getSelfNodeId(), label);
            viewChangeHandler.requestViewChange(label);
        } catch (Exception e) {
            log.warn("[{}] Fatal-attack view-change request failed: {}", nodeState.getSelfNodeId(), e.getMessage());
        }
    }


    private static boolean isFinalOk(ClientReply r) {
        if (r == null) return false;
        try {
            String result = r.getResult().trim().toUpperCase(Locale.ROOT);
            if (result.startsWith("BALANCE=")) return true;
            if (result.startsWith("OK")) return true;
            if (result.startsWith("SUCCESS")) return true;
            if (result.startsWith("FAIL")) return true;
            return false;
        } catch (Exception e) {
            return false;
        }
    }


    private record TransferPlanEntry(String raw,
                                     String from,
                                     String to,
                                     long amount,
                                     String clientId,
                                     int ordinal,
                                     long timestamp) { }

    private static final class DeterministicTimestampSequencer {
        private final long base;
        private int ordinal = 0;

        DeterministicTimestampSequencer(int setIndex) {
            long sanitized = Integer.toUnsignedLong(setIndex <= 0 ? 1 : setIndex);
            this.base = sanitized << 32;
        }

        TransferPlanEntry next(String raw, String from, String to, long amount, String clientId) {
            int current = ++ordinal;
            long ts = base | Integer.toUnsignedLong(current);
            return new TransferPlanEntry(raw, from, to, amount, clientId, current, ts);
        }
    }

    private record TransferCommand(TransferPlanEntry spec) { }

    private class ClientContext {
        private final String clientId;
        private final List<TransferPlanEntry> failed;
        private final ExecutorService executor;
        private CompletableFuture<Void> tail = CompletableFuture.completedFuture(null);

        ClientContext(String clientId, List<TransferPlanEntry> failed) {
            this.clientId = clientId;
            this.failed = failed;
            this.executor = Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "csv-client-" + clientId);
                t.setDaemon(true);
                return t;
            });
        }

        CompletableFuture<Void> submit(TransferCommand command) {
            synchronized (this) {
                tail = tail.thenRunAsync(() -> process(command), executor);
                return tail;
            }
        }

        private void process(TransferCommand c) {
            try {
                // Use ReplicaClient's repeating timer loop until EXECUTED
                ClientReply finalReply = replicaClient.submitUntilExecuted(
                        c.spec().from(), c.spec().to(), c.spec().amount(), c.spec().clientId(), c.spec().timestamp(),
                        CLIENT_TIMEOUT, CLIENT_RETRY_EVERY, activeClientMaxWait);

                if (isFinalOk(finalReply)) {
                    log.info("[{}] Completed successfully: {}", c.spec().clientId(), c.spec().raw());
                    return;
                }

                log.error("[{}] No success before max wait → deferring {}", c.spec().clientId(), c.spec().raw());
                failed.add(c.spec());

            } catch (Exception e) {
                log.error("[{}] {} failed: {}", c.spec().clientId(), c.spec().raw(), e.getMessage());
                failed.add(c.spec());
            }
        }

        void shutdown() {
            executor.shutdownNow();
        }
    }

    private void broadcastAdminFlush(FlushKind mode) {
        try {
            flushLocalStateTransactional(mode);
        } catch (Exception e) {
            log.error(" Local flush failed before broadcast: {}", e.getMessage(), e);
        }
        if (mode == FlushKind.FULL && !retryBuffer.isEmpty()) {
            int dropped = retryBuffer.size();
            retryBuffer.clear();
            log.warn(" Dropped {} deferred tx(s) during FULL flush to avoid duplicate execution.", dropped);
        }
        if (mode == FlushKind.FULL) {
            try {
                broadcastAdminFlushToPeers();
                log.info(" Broadcasted adminFlush(FULL) to all replicas (excluding self).");
            } catch (Exception e) {
                log.error("Failed broadcasting adminFlush: {}", e.getMessage(), e);
            }
        } else {
            log.info(" Performed SOFT flush locally (no peer broadcast).");
        }
    }


    public void flushLocalStateTransactional() {
        flushLocalStateTransactional(FlushKind.FULL);
    }

    public void flushSoft() { flushLocalStateTransactional(FlushKind.SOFT); }
    public void flushFull() { flushLocalStateTransactional(FlushKind.FULL); }

    public void flushLocalStateTransactional(FlushKind mode) {
        TransactionTemplate template = new TransactionTemplate(transactionManager);
        template.executeWithoutResult(status -> performFlush(mode));
    }

    private void performFlush(FlushKind mode) {
        log.warn("[LOCAL] {} flush → clearing logs/timers{}",
                mode, mode==FlushKind.FULL ? ", resetting balances" : " (preserving balances)");

        if (byzantineService != null) {
            byzantineService.clearAttack();
            replicaClient.broadcastAttackConfig("", Set.of(), Set.of());
        }

        try {
            replicaLogRepository.deleteAll();
            log.info(" replica_log cleared.");
        } catch (Exception e) {
            log.error(" Failed to clear replica_log: {}", e.getMessage(), e);
        }
        if (readLogRepository != null) {
            try {
                readLogRepository.deleteAll();
                log.info(" read_log cleared.");
            } catch (Exception e) {
                log.error(" Failed to clear read_log: {}", e.getMessage(), e);
            }
        }

        if (mode == FlushKind.FULL) {
            try {
                checkpointService.clearAll();
            } catch (Exception e) {
                log.error("Failed to clear checkpoints: {}", e.getMessage(), e);
            }
            try {
                accountRepo.resetAllBalances(10L);
                em.flush();
                em.clear();
                log.info("All client balances set to 10 (DB flushed).");
            } catch (Exception e) {
                log.error(" Failed to reset client balances: {}", e.getMessage(), e);
            }
        }

        try {
            logLocalBalances(mode==FlushKind.FULL ? "Post-reset" : "Post-soft-flush (balances preserved)");
            nodeState.resetEphemeralState();
            nodeState.markActivity();
            nodeState.setLastCommitSequenceNumber(0);
            nodeState.setNextSequence(1);
            nodeState.resetExecutionState();
            executionService.resetDeduplicationCaches();
            commitPhaseHandler.resetLatches();
            viewChangeHandler.resetForFlush();
            prePreparePhaseHandler.resetDedupCaches();
            primaryImplementation.resetBonusFastPath();
            thresholdSignatureService.reset();
            log.info("In-memory state cleared; seq reset to 1, lastCommit=0.");
        } catch (Exception e) {
            log.error("Failed to reset node state: {}", e.getMessage(), e);
        }
    }

    private long fetchAuthoritativeBalance(String setLabel, String account) {
        if (account == null || account.isBlank()) return 0L;

        if (shouldProxyBalance()) {
            try {
                String clientId = "csv-" + setLabel + "-balance-" + account.toLowerCase(Locale.ROOT);
                ClientReply reply = replicaClient.queryBalance(
                        account,
                        clientId,
                        CLIENT_TIMEOUT,
                        CLIENT_RETRY_EVERY,
                        activeClientMaxWait
                );
                Long remote = extractBalance(reply);
                if (remote != null) {
                    return remote;
                }
            } catch (Exception e) {
                log.warn("[{}] Remote balance query for {} failed: {}",
                        nodeState.getSelfNodeId(), account, e.getMessage());
            }
        }

        try {
            List<Long> results = em.createQuery(
                            "SELECT COALESCE(a.balance, 0) FROM ClientAccountEntity a WHERE a.name = :name",
                            Long.class)
                    .setParameter("name", account)
                    .setHint("org.hibernate.readOnly", Boolean.TRUE)
                    .getResultList();
            return results.isEmpty() ? 0L : Optional.ofNullable(results.get(0)).orElse(0L);
        } catch (Exception e) {
            log.error("[{}] Failed to fetch balance for {}: {}", nodeState.getSelfNodeId(), account, e.getMessage(), e);
            return 0L;
        }
    }

    private boolean shouldProxyBalance() {
        if (byzantineService != null && byzantineService.isCrashed(nodeState.getSelfNodeId())) {
            return true;
        }
        return !nodeState.isParticipating();
    }

    private Long extractBalance(ClientReply reply) {
        if (reply == null) return null;
        String result = reply.getResult();
        if (result == null) return null;
        String trimmed = result.trim();
        if (!trimmed.regionMatches(true, 0, "BALANCE=", 0, "BALANCE=".length())) {
            return null;
        }
        String numeric = trimmed.substring("BALANCE=".length()).trim();
        try {
            return Long.parseLong(numeric);
        } catch (NumberFormatException e) {
            log.warn("[{}] Unable to parse remote balance '{}'", nodeState.getSelfNodeId(), result);
            return null;
        }
    }

    private void logLocalBalances(String context) {
        try {
            List<Object[]> rows = em.createQuery(
                            "SELECT a.name, COALESCE(a.balance, 0) FROM ClientAccountEntity a ORDER BY a.name",
                            Object[].class)
                    .setHint("org.hibernate.readOnly", Boolean.TRUE)
                    .getResultList();

            String snapshot = rows.stream()
                    .map(row -> {
                        String name = String.valueOf(row[0]);
                        long balance = Optional.ofNullable(row[1])
                                .map(Number.class::cast)
                                .map(Number::longValue)
                                .orElse(0L);
                        return name + "=" + balance;
                    })
                    .collect(Collectors.joining(", "));
            log.warn("[{}] {} balances → {}", nodeState.getSelfNodeId(), context, snapshot);
        } catch (Exception e) {
            log.error("[{}] Failed to log balances for {}: {}", nodeState.getSelfNodeId(), context, e.getMessage(), e);
        }
    }

    public void broadcastAdminFlushToPeers() {
        for (var peer : nodeState.getClusterConfig().getNodes()) {
            if (peer.getId() == nodeState.getNodeId()) continue; // skip self
            ManagedChannel ch = null;
            try {
                ch = ManagedChannelBuilder
                        .forAddress(peer.getHost(), peer.getGrpcPort())
                        .usePlaintext()
                        .build();

                PbftServiceGrpc.PbftServiceBlockingStub stub =
                        PbftServiceGrpc.newBlockingStub(ch).withWaitForReady();

                stub.adminFlush(Empty.getDefaultInstance());
            } catch (Exception e) {
                log.warn(" adminFlush to {}:{} failed: {}", peer.getHost(), peer.getGrpcPort(), e.getMessage());
            } finally {
                if (ch != null) {
                    ch.shutdown();
                    try {
                        if (!ch.awaitTermination(500, TimeUnit.MILLISECONDS)) {
                            ch.shutdownNow();
                            ch.awaitTermination(500, TimeUnit.MILLISECONDS);
                        }
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                }
            }
        }
    }

    private void waitForQuiescence(Duration stableFor, Duration pollEvery) throws InterruptedException {
        int last = nodeState.getLastCommitSequenceNumber();
        Instant quietSince = Instant.now();
        Instant start = Instant.now();
        Duration maxWait = Duration.ofSeconds(15);

        while (true) {
            Thread.sleep(pollEvery.toMillis());
            int cur = nodeState.getLastCommitSequenceNumber();
            if (cur != last) {
                last = cur;
                quietSince = Instant.now();
            }
            if (Duration.between(quietSince, Instant.now()).compareTo(stableFor) >= 0) {
                log.info("Quiescent: lastCommitSequenceNumber stable at {}", last);
                return;
            }
            if (Duration.between(start, Instant.now()).compareTo(maxWait) >= 0) {
                log.warn("Quiescence wait timed out after {}, continuing (lastCommit={})", maxWait, last);
                return;
            }
        }
    }

    private List<ScenarioSet> parseSets(Iterable<CSVRecord> records) {
        List<ScenarioSet> sets = new ArrayList<>();
        ScenarioSet.Builder current = null;
        int autoIdx = 0;

        for (CSVRecord r : records) {
            String rawLine = r.toString();
            String[] fields = CSV_SAFE_SPLIT.split(rawLine);

            String setNumber = safe(r, "Set Number");
            String liveRaw   = firstNonBlank(r, "Live", "Live Nodes");
            String byzRaw    = firstNonBlank(r, "Byzantine"); // optional
            String atkRaw    = firstNonBlank(r, "Attack");
            atkRaw = fixAttackField(atkRaw, fields, r.size());
            String txRaw     = firstNonBlank(r, "Transactions");

            boolean newSet = (current == null) || !setNumber.isBlank();
            if (newSet) {
                if (current != null) sets.add(current.build());
                current = new ScenarioSet.Builder(++autoIdx, setNumber);
            }
            if (current == null) continue;

            if (!liveRaw.isBlank()) current.live(liveRaw);
            if (!byzRaw.isBlank())  current.byz(byzRaw);
            if (!atkRaw.isBlank())  current.attack(atkRaw);
            if (!txRaw.isBlank())   current.addTransactions(tokenize(txRaw));
        }

        if (current != null) sets.add(current.build());
        return sets;
    }

    private void applyLiveSet(String liveRaw, String byzRaw, String attackRaw) {
        fatalAttackActive = false;
        try {
            String ar = attackRaw == null ? "" : attackRaw.toLowerCase(Locale.ROOT);
            boolean slowScenario =
                    ar.contains("crash")
                            || ar.contains("equivoc")
                            || ar.contains("dark")
                            || ar.contains("partition")
                            || ar.contains("delay");
            if (!slowScenario && byzRaw != null && !byzRaw.isBlank()) {
                slowScenario = true;
            }
            Duration base = slowScenario ? CLIENT_MAX_WAIT_SLOW : CLIENT_MAX_WAIT;
            activeClientMaxWait = (pbftTimerService != null)
                    ? pbftTimerService.recommendedClientMaxWait(base)
                    : base;
        } catch (Exception ignored) {
            activeClientMaxWait = CLIENT_MAX_WAIT;
        }
        String cleanLive = (liveRaw == null) ? "" : liveRaw.trim();
        if (cleanLive.startsWith("\"")) cleanLive = cleanLive.substring(1);
        if (cleanLive.endsWith("\"")) cleanLive = cleanLive.substring(0, cleanLive.length() - 1);

        if (cleanLive.isBlank()) {
            log.info("Live set not specified; keeping current membership.");
        }

        Set<Integer> lives = parseRoster(liveRaw);
        Set<Integer> byzantines = parseRoster(byzRaw);
        Set<Integer> attackDirectiveNodes = parseAttackNodes(attackRaw);
        Set<Integer> darkVictims = parseDarkVictims(attackRaw);
        Set<Integer> equivVictims = parseEquivocateVictims(attackRaw);
        attackDirectiveNodes.removeAll(equivVictims);
        attackDirectiveNodes.removeAll(darkVictims);
        Set<Integer> allVictims = new LinkedHashSet<>(darkVictims);
        allVictims.addAll(equivVictims);

        String attackDirective = attackRaw == null ? "" : attackRaw.trim();
        Set<String> attackModes = parseAttackModes(attackDirective);
        Set<Integer> effectiveAttackNodes = !byzantines.isEmpty() ? byzantines : attackDirectiveNodes;
        boolean fastPathUnsafe = attackModes.stream()
                .map(String::toLowerCase)
                .anyMatch(FAST_PATH_BLOCKERS::contains);
        if (primaryImplementation != null && fastPathUnsafe) {
            primaryImplementation.suspendBonusFastPath(
                    attackDirective.isBlank() ? "CSV scenario disabled fast path (crash attack)" : attackDirective);
        }

        if (byzantineService != null) {
            if (!attackModes.isEmpty() && (!effectiveAttackNodes.isEmpty() || !darkVictims.isEmpty())) {
                byzantineService.configureAttack(attackDirective, effectiveAttackNodes, allVictims);

                String self = nodeState.getSelfNodeId();
                int selfNum = extractNodeNumSafe(self);
                if (selfNum >= 0 && effectiveAttackNodes.contains(selfNum)) {
                    byzantineService.markSelfCrashed(self, attackDirective);
                    log.warn("[{}] Self-activated attack '{}' → {}", self, attackDirective, byzantineService.describe());
                }

                replicaClient.broadcastAttackConfig(attackDirective, effectiveAttackNodes, allVictims);
                log.warn("Activated attack '{}' on Byzantine nodes: {} (victims={} darkVictims={})",
                        attackDirective, effectiveAttackNodes, allVictims, darkVictims);
            } else {
                byzantineService.clearAttack();
                replicaClient.broadcastAttackConfig("", Set.of(), Set.of());
                if (attackRaw != null && !attackRaw.isBlank())
                    log.info("No actionable attack found (raw='{}'), cleared any previous attack.", attackRaw);
            }
        }

        boolean signAttack = attackModes.stream().anyMatch(mode -> mode.equalsIgnoreCase("sign"));
        int liveCount = lives.isEmpty() ? nodeState.getLiveNodes().size() : lives.size();
        int maliciousCount = effectiveAttackNodes.size();
        int honestCount = Math.max(0, liveCount - maliciousCount);
        currentHonestNodes = honestCount;
        boolean honestBelowQuorum = honestCount < nodeState.quorumSize();
        fatalAttackActive = honestBelowQuorum || (signAttack && honestBelowQuorum);
        if (fatalAttackActive) {
            log.warn("[{}] Attack '{}' leaves only {} honest node(s) < quorum {} → treating set as fatal.",
                    nodeState.getSelfNodeId(), attackDirective, honestCount, nodeState.quorumSize());
            activeClientMaxWait = Duration.ofSeconds(5);
        }

        if (!lives.isEmpty()) {
            nodeState.replaceLiveSet(lives);
            log.info("[{}] Applied Live set: {}", nodeState.getSelfNodeId(), lives);
            replicaClient.broadcastRoster(lives, nodeState.getDeadNodes());
        }
        log.info("[{}] Dead nodes now = {}", nodeState.getSelfNodeId(), nodeState.getDeadNodes());
    }

    private Set<Integer> parseAttackNodes(String raw) {
        Set<Integer> out = new LinkedHashSet<>();
        if (raw == null) return out;
        Matcher m = N_PATTERN.matcher(raw);
        while (m.find()) {
            try { out.add(Integer.parseInt(m.group(1))); } catch (NumberFormatException ignored) {}
        }
        return out;
    }

    private Set<Integer> parseDarkVictims(String raw) {
        Set<Integer> out = new LinkedHashSet<>();
        if (raw == null) return out;
        Matcher matcher = DARK_PATTERN.matcher(raw);
        while (matcher.find()) {
            String body = matcher.group(1);
            if (body == null || body.isBlank()) continue;
            for (String token : body.split("[,\\s]+")) {
                if (token.isBlank()) continue;
                try {
                    out.add(Integer.parseInt(token.replaceAll("[^0-9]", "")));
                } catch (NumberFormatException ignored) { }
            }
        }
        return out;
    }

    private Set<Integer> parseEquivocateVictims(String raw) {
        Set<Integer> out = new LinkedHashSet<>();
        if (raw == null || raw.isBlank()) return out;

        String s = raw;
        String lower = s.toLowerCase(Locale.ROOT);
        int idx = lower.indexOf("equivocat"); // matches 'equivocate' or 'equivocation'
        if (idx < 0) return out;

        // Move to the opening '(' after the keyword
        int open = lower.indexOf('(', idx);
        if (open < 0) return out;

        // Scan forward until the matching ')' while ignoring anything inside square brackets
        int parenDepth = 0;
        boolean inSquare = false;
        StringBuilder buf = new StringBuilder();
        for (int i = open + 1; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '[') { inSquare = true; continue; }
            if (c == ']') { inSquare = false; continue; }
            if (inSquare) continue; // ignore bracketed lists

            if (c == '(') { parenDepth++; continue; }
            if (c == ')') {
                if (parenDepth == 0) break; // end of our equivocate(..)
                parenDepth--; continue;
            }
            buf.append(c);
        }

        for (String token : buf.toString().split("[,\\s]+")) {
            String digits = token.replaceAll("[^0-9]", "");
            if (digits.isEmpty()) continue;
            try { out.add(Integer.parseInt(digits)); } catch (NumberFormatException ignored) { }
        }
        return out;
    }

    private Set<String> parseAttackModes(String raw) {
        if (raw == null) return Collections.emptySet();
        String normalized = raw.trim().toLowerCase(Locale.ROOT)
                .replace("[", "")
                .replace("]", "");
        if (normalized.isBlank()) return Collections.emptySet();

        Set<String> out = new LinkedHashSet<>();
        Set<String> allow = Set.of("equivocate", "equivocation", "dark", "crash", "time", "sign");
        for (String token : normalized.split("[^a-z]+")) {
            if (token.isBlank()) continue;
            String t = token;
            if ("equivocation".equals(t)) t = "equivocate";
            if (t.length() == 1 && t.charAt(0) == 'n') continue; // skip stray 'n' from n#
            if (!allow.contains(t)) continue;
            // convert to canonical (equivocation -> equivocate)
            if ("equivocation".equals(t)) t = "equivocate";
            out.add(t);
        }
        return out;
    }

    private static int extractNodeNumSafe(String nodeId) {
        if (nodeId == null) return -1;
        String digits = nodeId.replaceAll("[^0-9]", "");
        if (digits.isEmpty()) return -1;
        try { return Integer.parseInt(digits); } catch (NumberFormatException e) { return -1; }
    }

    private static String safe(CSVRecord r, String key) {
        try { return Optional.ofNullable(r.get(key)).orElse("").trim(); }
        catch (IllegalArgumentException e) { return ""; }
    }

    private static String firstNonBlank(CSVRecord r, String... keys) {
        for (String k : keys) {
            String v = safe(r, k);
            if (!v.isBlank()) return v;
        }
        return "";
    }

    private static List<String> tokenize(String txList) {
        List<String> out = new ArrayList<>();
        if (txList == null || txList.isBlank()) return out;
        for (String raw : txList.replace("\"", "").trim().split(";")) {
            String t = raw.trim();
            if (!t.isEmpty()) out.add(t);
        }
        return out;
    }

    private record ScenarioSet(int index, String label, String liveRaw, String byzRaw,
                               String attackRaw, List<String> transactions) {
        private static class Builder {
            private final int index;
            private final String label;
            private String liveRaw = "";
            private String byzRaw = "";
            private String attackRaw = "";
            private final List<String> transactions = new ArrayList<>();

            private Builder(int index, String setNumber) {
                this.index = index;
                this.label = (setNumber == null || setNumber.isBlank())
                        ? String.valueOf(index) : setNumber.trim();
            }

            private Builder live(String value)   { this.liveRaw = value; return this; }
            private Builder byz(String value)    { this.byzRaw = value; return this; }
            private Builder attack(String value) { this.attackRaw = value; return this; }
            private Builder addTransactions(List<String> txs) { this.transactions.addAll(txs); return this; }

            private ScenarioSet build() {
                return new ScenarioSet(index, label,
                        (liveRaw == null ? "" : liveRaw),
                        (byzRaw == null ? "" : byzRaw),
                        (attackRaw == null ? "" : attackRaw),
                        List.copyOf(transactions));
            }
        }
    }

    private Set<Integer> parseRoster(String raw) {
        Set<Integer> out = new LinkedHashSet<>();
        if (raw == null) return out;

        String body = raw.replaceAll("[\\[\\]\"]", "").trim(); // remove brackets + quotes
        if (body.isEmpty()) return out;

        for (String token : body.split("[,;]")) {
            String t = token.trim();
            if (t.isEmpty()) continue;
            if (t.startsWith("n") || t.startsWith("N")) t = t.substring(1);
            try {
                out.add(Integer.parseInt(t));
            } catch (NumberFormatException e) {
                log.warn("Ignoring malformed node token '{}'", token);
            }
        }

        log.info("Parsed live roster → {}", out);
        return out;
    }

    private static void waitForEnter() {
        try {
            if (System.console() != null) {
                System.console().readLine();
            } else if (STDIN != null) {
                synchronized (INPUT_LOCK) {
                    while (STDIN.ready()) STDIN.readLine();
                    STDIN.readLine();
                }
            }
        } catch (Exception ignored) { }
    }

    private static String fixAttackField(String raw, String[] extraFields, int recordSize) {
        if (raw == null) return "";
        String s = raw.trim();
        if (s.isBlank()) return s;

        // Stitch back comma-separated fragments that were split into extra CSV cells.
        int idx = Math.max(recordSize, 0);
        while (!delimitersBalanced(s) && extraFields != null && idx < extraFields.length) {
            String fragment = extraFields[idx++].trim();
            if (!fragment.isEmpty()) {
                s = s + "," + fragment;
            }
        }

        if (hasMoreOf(s, '[', ']')) s = s + "]";
        if (hasMoreOf(s, '(', ')')) s = s + ")";

        s = s.replaceAll("\\s+", " ")
                .replaceAll("\\[+", "[")
                .replaceAll("\\]+", "]");

        s = s.replaceAll("\\],\\s*\\[", "],[");

        StringBuilder out = new StringBuilder(s.length() + 8);
        boolean inDark = false;
        int parenDepth = 0;

        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);

            if (!inDark && i + 5 <= s.length() && s.regionMatches(true, i, "dark(", 0, 5)) {
                inDark = true;
                parenDepth = 1;
                out.append("dark(");
                i += 4;
                continue;
            }

            if (inDark) {
                if (c == '(') parenDepth++;
                if (c == ')') {
                    parenDepth--;
                    if (parenDepth <= 0) { inDark = false; parenDepth = 0; }
                }
                if (c == ']' && parenDepth > 0) {
                    out.append(')');
                    inDark = false;
                    parenDepth = 0;
                }
            }

            out.append(c);
        }

        if (inDark || parenDepth > 0) out.append(')');

        return out.toString();
    }

    private static boolean delimitersBalanced(String s) {
        int paren = 0, square = 0;
        for (char c : s.toCharArray()) {
            if (c == '(') paren++;
            else if (c == ')') {
                paren--;
                if (paren < 0) return false;
            } else if (c == '[') square++;
            else if (c == ']') {
                square--;
                if (square < 0) return false;
            }
        }
        return paren == 0 && square == 0;
    }

    private static boolean hasMoreOf(String s, char open, char close) {
        int balance = 0;
        for (char c : s.toCharArray()) {
            if (c == open) balance++;
            if (c == close) balance--;
        }
        return balance > 0;
    }
}
