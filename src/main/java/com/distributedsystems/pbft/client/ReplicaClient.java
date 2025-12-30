package com.distributedsystems.pbft.client;

import com.distributedsystems.pbft.exe.ClusterConfig;
import com.distributedsystems.pbft.proto.*;
import com.distributedsystems.pbft.service.ByzantineService;
import com.distributedsystems.pbft.service.ClientRequestAuthenticator;
import com.distributedsystems.pbft.state.NodeState;
import io.grpc.Context;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Function;

@Component
@RequiredArgsConstructor(onConstructor_ = {@Lazy})
public class ReplicaClient {

    private static final Logger log = LoggerFactory.getLogger(ReplicaClient.class);

    private static final long RPC_DEADLINE_SECS = 30;
    private static final long CHANNEL_SHUTDOWN_MS = 500;

    private static final Duration PRIMARY_ATTEMPT_TIMEOUT   = Duration.ofMillis(1500);
    private static final Duration BROADCAST_ATTEMPT_TIMEOUT = Duration.ofSeconds(6);

    private static final int MAX_BROADCAST_THREADS = 8;

    private final NodeState nodeState;
    private final ClientRequestAuthenticator clientRequestAuthenticator;

    @Autowired
    private ByzantineService byzantineService;

    private static final boolean ENABLE_CLIENT_CALLBACK = false;
    private static final String  CLIENT_CALLBACK_HOST   = "localhost";
    private static final int     CLIENT_CALLBACK_PORT   = 10000; // change if you really run a client listener

    private final ConcurrentHashMap<String, ManagedChannel> channelCache = new ConcurrentHashMap<>();

    private ManagedChannel getOrCreateChannel(ClusterConfig.NodeMetaData node) {
        String key = node.getHost() + ":" + node.getGrpcPort();
        return channelCache.computeIfAbsent(key, k ->
                ManagedChannelBuilder.forAddress(node.getHost(), node.getGrpcPort())
                        .usePlaintext()
                        .build());
    }

    private PbftServiceGrpc.PbftServiceBlockingStub newStub(ManagedChannel ch) {
        return PbftServiceGrpc.newBlockingStub(ch)
                .withWaitForReady()
                .withDeadlineAfter(RPC_DEADLINE_SECS, TimeUnit.SECONDS);
    }

    private <T> T callRpc(
            ClusterConfig.NodeMetaData target,
            Function<PbftServiceGrpc.PbftServiceBlockingStub, T> fn,
            String what
    ) {
        try {
            ManagedChannel channel = getOrCreateChannel(target);
            var stub = newStub(channel);
            return fn.apply(stub);
        } catch (Exception e) {
            log.error("[ReplicaClient] {} → {}:{} failed: {}", what, target.getHost(), target.getGrpcPort(), e.getMessage());
            return null;
        }
    }

    private Acknowledge unaryTo(
            ClusterConfig.NodeMetaData target,
            Function<PbftServiceGrpc.PbftServiceBlockingStub, Acknowledge> fn,
            String what
    ) {
        String selfId = nodeState.getSelfNodeId();
        String targetId = "node-" + target.getId();
        if (byzantineService != null && byzantineService.shouldSuppressSend(selfId, targetId)) {
            log.warn("[{}] Suppressed {} → {}:{} (attack mode)", selfId, what, target.getHost(), target.getGrpcPort());
            return Acknowledge.newBuilder().setSuccess(false).setMessage("Suppressed by Byzantine attack").build();
        }

        Acknowledge ack = callRpc(target, fn, what);
        if (ack == null) {
            return Acknowledge.newBuilder().setSuccess(false).setMessage("RPC failed").build();
        }
        return ack;
    }

    private List<Acknowledge> broadcastToAll(
            List<ClusterConfig.NodeMetaData> targets,
            Function<PbftServiceGrpc.PbftServiceBlockingStub, Acknowledge> fn,
            String phaseName
    ) {
        if (targets == null || targets.isEmpty()) return List.of();

        List<ClusterConfig.NodeMetaData> eligible = new ArrayList<>(targets.size());
        for (var node : targets) {
            String nodeId = "node-" + node.getId();
            if (!nodeState.isLive(nodeId)) {
                log.debug("[ReplicaClient] Skipping dead peer {} for {}", nodeId, phaseName);
                continue;
            }
            if (byzantineService != null
                    && byzantineService.shouldSuppressSend(nodeState.getSelfNodeId(), nodeId)) {
                log.warn("[{}] Suppressed {} → {}:{} (attack mode)",
                        nodeState.getSelfNodeId(), phaseName, node.getHost(), node.getGrpcPort());
                continue;
            }
            eligible.add(node);
        }

        if (eligible.isEmpty()) return List.of();
        if (eligible.size() == 1) {
            return List.of(invokePhase(eligible.get(0), fn, phaseName));
        }

        int poolSize = Math.min(Math.max(1, eligible.size()), MAX_BROADCAST_THREADS);
        ExecutorService executor = Executors.newFixedThreadPool(poolSize, r -> {
            Thread t = new Thread(r, "pbft-broadcast-" + phaseName);
            t.setDaemon(true);
            return t;
        });

        try {
            List<CompletableFuture<Acknowledge>> futures = new ArrayList<>(eligible.size());
            for (var node : eligible) {
                futures.add(CompletableFuture.supplyAsync(
                        () -> invokePhase(node, fn, phaseName), executor));
            }

            List<Acknowledge> results = new ArrayList<>(futures.size());
            for (CompletableFuture<Acknowledge> f : futures) {
                try {
                    results.add(f.get(RPC_DEADLINE_SECS + 2, TimeUnit.SECONDS));
                } catch (TimeoutException te) {
                    results.add(Acknowledge.newBuilder()
                            .setSuccess(false)
                            .setMessage("ERR: timeout waiting for ack").build());
                } catch (Exception e) {
                    results.add(Acknowledge.newBuilder()
                            .setSuccess(false)
                            .setMessage("ERR: " + e.getMessage()).build());
                }
            }
            return results;
        } finally {
            executor.shutdownNow();
        }
    }

    private Acknowledge invokePhase(ClusterConfig.NodeMetaData node,
                                    Function<PbftServiceGrpc.PbftServiceBlockingStub, Acknowledge> fn,
                                    String phaseName) {
        Context prev = Context.ROOT.attach();
        try {
            ManagedChannel channel = getOrCreateChannel(node);
            var stub = newStub(channel);
            return fn.apply(stub);
        } catch (Exception e) {
            log.error("[ReplicaClient]  {} to {}:{} failed: {}",
                    phaseName, node.getHost(), node.getGrpcPort(), e.getMessage());
            return Acknowledge.newBuilder()
                    .setSuccess(false)
                    .setMessage("ERR: " + e.getMessage())
                    .build();
        } finally {
            Context.ROOT.detach(prev);
        }
    }

    public Acknowledge sendPrepareToLeader(Prepare prepare, ClusterConfig.NodeMetaData leaderMeta) {
        return unaryTo(leaderMeta, stub -> stub.preparePhase(prepare),
                String.format("PREPARE(seq=%d,digest=%s)", prepare.getSequence(), prepare.getDigest()));
    }

    public Acknowledge sendCommitToLeader(Commit commit, ClusterConfig.NodeMetaData leaderMeta) {
        return unaryTo(leaderMeta, stub -> stub.commitPhase(commit),
                String.format("COMMIT(seq=%d,digest=%s)", commit.getSequence(), commit.getDigest()));
    }

    public List<Acknowledge> broadcastPrePrepare(PrePrepare pre, List<ClusterConfig.NodeMetaData> targets) {
        return broadcastToAll(targets, stub -> stub.prePreparePhase(pre), "PRE-PREPARE");
    }

    public Acknowledge sendPrePrepareToPeer(PrePrepare pre, ClusterConfig.NodeMetaData target) {
        return unaryTo(target, stub -> stub.prePreparePhase(pre), "PRE-PREPARE");
    }

    public List<Acknowledge> broadcastPrepare(Prepare prepare, List<ClusterConfig.NodeMetaData> targets) {
        return broadcastToAll(targets, stub -> stub.preparePhase(prepare), "PREPARE");
    }

    public List<Acknowledge> broadcastCommit(Commit commit, List<ClusterConfig.NodeMetaData> targets) {
        return broadcastToAll(targets, stub -> stub.commitPhase(commit), "COMMIT");
    }

    public Acknowledge sendCheckpointProofToLeader(CheckpointProofMessage message, ClusterConfig.NodeMetaData leaderMeta) {
        String what = message.hasSummary()
                ? String.format("CHECKPOINT_PROOF(seq=%d,digest=%s)", message.getSummary().getSequence(), message.getSummary().getDigest())
                : "CHECKPOINT_PROOF";
        return unaryTo(leaderMeta, stub -> stub.checkpointProofPhase(message), what);
    }

    public List<Acknowledge> broadcastCheckpointCertificate(CheckpointCertificateBroadcast broadcast, List<ClusterConfig.NodeMetaData> targets) {
        return broadcastToAll(targets, stub -> stub.checkpointCertificatePhase(broadcast), "CHECKPOINT-CERT");
    }

    public Optional<CheckpointState> fetchCheckpointState(long seq, String digest, ClusterConfig.NodeMetaData target) {
        CheckpointStateRequest req = CheckpointStateRequest.newBuilder()
                .setSequence(seq)
                .setDigest(digest == null ? "" : digest)
                .setRequester(nodeState.getSelfNodeId())
                .build();
        String selfId = nodeState.getSelfNodeId();
        String targetId = "node-" + target.getId();
        if (byzantineService != null && byzantineService.shouldSuppressSend(selfId, targetId)) {
            log.warn("[{}] Suppressed CHECKPOINT_STATE → {}:{} (attack mode)", selfId, target.getHost(), target.getGrpcPort());
            return Optional.empty();
        }
        CheckpointState response = callRpc(target, stub -> stub.getCheckpointState(req),
                String.format("CHECKPOINT_STATE(seq=%d,digest=%s)", seq, digest));
        if (response == null) return Optional.empty();
        if (response.getSerializedStateJson().isBlank()) return Optional.empty();
        return Optional.of(response);
    }

    public List<Acknowledge> broadcastPrepareCertificate(PrepareCertificate cert, List<ClusterConfig.NodeMetaData> targets) {
        return broadcastToAll(targets, stub -> stub.prepareCertificatePhase(cert), "PREPARE_CERTIFICATE");
    }

    public List<Acknowledge> broadcastCommitCertificate(CommitCertificate cert, List<ClusterConfig.NodeMetaData> targets) {
        return broadcastToAll(targets, stub -> stub.commitCertificatePhase(cert), "COMMIT_CERTIFICATE");
    }

    public List<Acknowledge> broadcastViewChange(ViewChange vc, List<ClusterConfig.NodeMetaData> targets) {
        return broadcastToAll(targets, stub -> stub.viewChangePhase(vc), "VIEW_CHANGE");
    }

    public List<Acknowledge> broadcastNewView(NewView nv, List<ClusterConfig.NodeMetaData> targets) {
        return broadcastToAll(targets, stub -> stub.newViewPhase(nv), "NEW_VIEW");
    }

    public void broadcastAttackConfig(String attackDirective, Set<Integer> nodes, Set<Integer> victims) {
        var targets = nodeState.livePeersExcludingSelf();
        if (targets.isEmpty()) return;

        AttackConfig.Builder builder = AttackConfig.newBuilder()
                .setAttackType(attackDirective == null ? "" : attackDirective)
                .setClear((attackDirective == null || attackDirective.isBlank())
                        && (nodes == null || nodes.isEmpty())
                        && (victims == null || victims.isEmpty()));
        if (nodes != null) builder.addAllNodes(nodes);
        if (victims != null) builder.addAllVictims(victims);
        AttackConfig request = builder.build();

        int poolSize = Math.min(Math.max(1, targets.size()), MAX_BROADCAST_THREADS);
        ExecutorService executor = Executors.newFixedThreadPool(poolSize, r -> {
            Thread t = new Thread(r, "pbft-broadcast-attack");
            t.setDaemon(true);
            return t;
        });

        try {
            List<CompletableFuture<Acknowledge>> futures = new ArrayList<>(targets.size());
            for (var meta : targets) {
                futures.add(CompletableFuture.supplyAsync(() -> {
                    try {
                        ManagedChannel channel = getOrCreateChannel(meta);
                        var stub = newStub(channel);
                        return stub.adminAttack(request);
                    } catch (Exception e) {
                        log.warn("[{}] Attack broadcast to {}:{} failed: {}", nodeState.getSelfNodeId(), meta.getHost(), meta.getGrpcPort(), e.getMessage());
                        return Acknowledge.newBuilder().setSuccess(false).setMessage("ATTACK_BROADCAST_FAILED").build();
                    }
                }, executor));
            }
            for (var f : futures) {
                try { f.get(RPC_DEADLINE_SECS + 2, TimeUnit.SECONDS); } catch (Exception ignored) {}
            }
        } finally {
            executor.shutdownNow();
        }
    }

    public void broadcastRoster(Set<Integer> live, Set<Integer> dead) {
        List<ClusterConfig.NodeMetaData> targets = new ArrayList<>(nodeState.getClusterConfig().getNodes());
        targets.removeIf(meta -> meta.getId() == nodeState.getNodeId());
        if (targets.isEmpty()) return;

        RosterConfig request = RosterConfig.newBuilder().addAllLive(live).addAllDead(dead == null ? List.of() : dead).build();

        int poolSize = Math.min(Math.max(1, targets.size()), MAX_BROADCAST_THREADS);
        ExecutorService executor = Executors.newFixedThreadPool(poolSize, r -> {
            Thread t = new Thread(r, "pbft-broadcast-roster");
            t.setDaemon(true);
            return t;
        });

        try {
            List<CompletableFuture<Void>> futures = new ArrayList<>(targets.size());
            for (var meta : targets) {
                futures.add(CompletableFuture.runAsync(() -> {
                    try {
                        ManagedChannel channel = getOrCreateChannel(meta);
                        var stub = newStub(channel);
                        stub.adminRoster(request);
                    } catch (Exception e) {
                        log.warn("[{}] Roster broadcast to {}:{} failed: {}", nodeState.getSelfNodeId(), meta.getHost(), meta.getGrpcPort(), e.getMessage());
                    }
                }, executor));
            }
            for (var f : futures) {
                try { f.get(RPC_DEADLINE_SECS + 2, TimeUnit.SECONDS); } catch (Exception ignored) {}
            }
        } finally {
            executor.shutdownNow();
        }
    }

    public void broadcastTimerControl(boolean pause, String reason) {
        List<ClusterConfig.NodeMetaData> targets = nodeState.livePeersExcludingSelf();
        if (targets.isEmpty()) return;

        TimerControl request = TimerControl.newBuilder()
                .setPause(pause)
                .setReason(reason == null ? "" : reason)
                .build();

        int poolSize = Math.min(Math.max(1, targets.size()), MAX_BROADCAST_THREADS);
        ExecutorService executor = Executors.newFixedThreadPool(poolSize, r -> {
            Thread t = new Thread(r, "pbft-broadcast-timer");
            t.setDaemon(true);
            return t;
        });

        try {
            List<CompletableFuture<Void>> futures = new ArrayList<>(targets.size());
            for (var meta : targets) {
                futures.add(CompletableFuture.runAsync(() -> {
                    try {
                        ManagedChannel channel = getOrCreateChannel(meta);
                        var stub = newStub(channel);
                        stub.adminTimer(request);
                    } catch (Exception e) {
                        log.warn("[{}] Timer broadcast to {}:{} failed: {}",
                                nodeState.getSelfNodeId(), meta.getHost(), meta.getGrpcPort(), e.getMessage());
                    }
                }, executor));
            }
            for (var f : futures) {
                try { f.get(RPC_DEADLINE_SECS + 2, TimeUnit.SECONDS); } catch (Exception ignored) {}
            }
        } finally {
            executor.shutdownNow();
        }
    }

    private static boolean isFinalSuccess(ClientReply reply) {
        if (reply == null) return false;
        try {
            String r = String.valueOf(reply.getResult());
            if (r == null || r.isBlank()) return false;
            String u = r.trim().toUpperCase(Locale.ROOT);
            if ("ACCEPTED".equals(u) || "LIVE_SET_IGNORE".equals(u)) return false;
            if (u.startsWith("BALANCE=")) return true;
            if (u.startsWith("OK")) return true;
            if (u.startsWith("SUCCESS")) return true;
            if (u.startsWith("FAIL")) return true;
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private ClientRequest buildSignedRequest(String operation,
                                             String from,
                                             String to,
                                             long amount,
                                             String clientId,
                                             long timestamp) {
        String op = (operation == null || operation.isBlank()) ? "TRANSFER" : operation;
        ClientRequest.Builder builder = ClientRequest.newBuilder()
                .setClientId(clientId == null ? "" : clientId)
                .setOperation(op)
                .setFromAccount(from == null ? "" : from)
                .setToAccount(to == null ? "" : to)
                .setAmount(amount)
                .setTimestamp(String.valueOf(timestamp));
        return clientRequestAuthenticator.sign(builder);
    }

    private ClientReply timeoutReply(String clientId, String self) {
        return ClientReply.newBuilder()
                .setSequence(0)
                .setResult("FAIL")
                .setReplicaId(self)
                .setClientId(clientId)
                .build();
    }

    public ClientReply submitUntilExecuted(String from,
                                           String to,
                                           long amount,
                                           String clientId,
                                           long timestamp,
                                           Duration perAttemptTimeout,
                                           Duration retryInterval) {
        return submitUntilExecuted("TRANSFER", from, to, amount, clientId, timestamp,
                perAttemptTimeout, retryInterval, Duration.ofSeconds(10));
    }

    public ClientReply submitUntilExecuted(String from,
                                           String to,
                                           long amount,
                                           String clientId,
                                           long timestamp,
                                           Duration perAttemptTimeout,
                                           Duration retryInterval,
                                           Duration maxWait) {
        return submitUntilExecuted("TRANSFER", from, to, amount, clientId, timestamp,
                perAttemptTimeout, retryInterval, maxWait);
    }

    public ClientReply submitUntilExecuted(String operation,
                                           String from,
                                           String to,
                                           long amount,
                                           String clientId,
                                           long timestamp,
                                           Duration perAttemptTimeout,
                                           Duration retryInterval,
                                           Duration maxWait) {
        // Keep a stable request identity across retries
        ClientRequest req = buildSignedRequest(
                operation,
                from,
                to,
                amount,
                clientId,
                timestamp
        );

        String self = nodeState.getSelfNodeId();
        long start = System.currentTimeMillis();
        int round = 0;
        ClientReply last = null;
        final long maxWaitMs = (maxWait != null && maxWait.toMillis() > 0) ? maxWait.toMillis() : -1L;

        while (true) {
            if (maxWaitMs > 0 && System.currentTimeMillis() - start >= maxWaitMs) {
                long elapsed = System.currentTimeMillis() - start;
                log.warn("[{}] submitUntilExecuted timeout after {} ms (round={})", self, elapsed, round);
                return timeoutReply(clientId, self);
            }

            // First try the current primary, then fall back to broadcasts
            ClusterConfig.NodeMetaData leaderMeta = resolveLeaderMeta();
            if (leaderMeta != null) {
                last = sendToPeer(req, leaderMeta,
                        perAttemptTimeout == null ? PRIMARY_ATTEMPT_TIMEOUT : perAttemptTimeout,
                        round == 0, true);
                if (isFinalSuccess(last)) return last;
                nodeState.updateLeader(targetKey(leaderMeta));
                if (maxWaitMs > 0 && System.currentTimeMillis() - start >= maxWaitMs) {
                    long elapsed = System.currentTimeMillis() - start;
                    log.warn("[{}] submitUntilExecuted timeout after {} ms (round={}) post-primary attempt",
                            self, elapsed, round);
                    return timeoutReply(clientId, self);
                }
            }

            List<ClusterConfig.NodeMetaData> targets = new ArrayList<>(nodeState.livePeersExcludingSelf());
            nodeState.nodeInfo(nodeState.getSelfNodeId()).ifPresent(targets::add);
            if (leaderMeta != null && targets.stream().noneMatch(n -> n.getId() == leaderMeta.getId())) {
                targets.add(leaderMeta);
            }
            Collections.shuffle(targets);

            for (var t : targets) {
                last = sendToPeer(req, t, BROADCAST_ATTEMPT_TIMEOUT, false, true);
                if (isFinalSuccess(last)) return last;
                if (maxWaitMs > 0 && System.currentTimeMillis() - start >= maxWaitMs) {
                    long elapsed = System.currentTimeMillis() - start;
                    log.warn("[{}] submitUntilExecuted timeout after {} ms (round={}) during broadcast",
                            self, elapsed, round);
                    return timeoutReply(clientId, self);
                }
            }

            // If still not successful, wait for retryInterval and try again.
            long sleepMs = (retryInterval == null || retryInterval.isZero() || retryInterval.isNegative())
                    ? 2000L : retryInterval.toMillis();
            long pause = Math.max(500L, sleepMs);
            if (maxWaitMs > 0) {
                long remaining = maxWaitMs - (System.currentTimeMillis() - start);
                if (remaining <= 0) {
                    long elapsed = System.currentTimeMillis() - start;
                    log.warn("[{}] submitUntilExecuted timeout after {} ms (round={}) before retry sleep",
                            self, elapsed, round);
                    return timeoutReply(clientId, self);
                }
                pause = Math.min(pause, Math.max(100L, remaining));
            }
            try { Thread.sleep(pause); } catch (InterruptedException ignored) { }
            round++;
        }
    }

    public ClientReply queryBalance(String account,
                                    String clientId,
                                    Duration perAttemptTimeout,
                                    Duration retryInterval,
                                    Duration maxWait) {
        return submitUntilExecuted("BALANCE", account, "", 0L,
                clientId, System.currentTimeMillis(),
                perAttemptTimeout, retryInterval, maxWait);
    }

    private ClusterConfig.NodeMetaData resolveLeaderMeta() {
        ClusterConfig.NodeMetaData meta = findMetaByEndpoint(nodeState.getPrimaryNodeId());
        if (meta != null) return meta;

        meta = findMetaByEndpoint(nodeState.getCurrentLeaderId());
        if (meta != null) return meta;

        String leaderId = nodeState.validPrimaryIdForView(nodeState.getCurrentView());
        return nodeState.nodeInfo(leaderId).orElse(null);
    }

    private ClientReply sendToPeer(ClientRequest req,
                                   ClusterConfig.NodeMetaData target,
                                   Duration timeout,
                                   boolean logPrimaryAttempt,
                                   boolean allowWhenCrashed) {
        String self = nodeState.getSelfNodeId();
        String peerAddr = target.getHost() + ":" + target.getGrpcPort();

        if (!allowWhenCrashed && byzantineService != null
                && byzantineService.shouldSuppressSend(self, "node-" + target.getId())) {
            log.warn("[{}] Suppressed client request to {} (attack mode)", self, peerAddr);
            return null;
        }

        try {
            if (logPrimaryAttempt) log.info("[{}] Primary attempt → {}", self, peerAddr);
            else                   log.info("[{}] Broadcast attempt → {}", self, peerAddr);

            ManagedChannel channel = getOrCreateChannel(target);

            long ms = Math.max(1000, timeout.toMillis()); // never <1s
            PbftServiceGrpc.PbftServiceBlockingStub stub =
                    PbftServiceGrpc.newBlockingStub(channel)
                            .withWaitForReady()
                            .withDeadlineAfter(ms, TimeUnit.MILLISECONDS);

            ClientReply reply = stub.submitClientRequest(req);
            if (reply == null) log.warn("[{}] Null reply from {}", self, peerAddr);
            else               log.info("[{}] Reply from {} → {}", self, peerAddr, reply.getResult());
            return reply;

        } catch (Exception e) {
            return null;
        }
    }

    @PreDestroy
    public void closeCachedChannels() {
        for (ManagedChannel ch : channelCache.values()) {
            try {
                ch.shutdown();
                ch.awaitTermination(CHANNEL_SHUTDOWN_MS, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                ch.shutdownNow();
            }
        }
        channelCache.clear();
    }

    private ClusterConfig.NodeMetaData findMetaByEndpoint(String endpoint) {
        if (endpoint == null || endpoint.isBlank()) return null;
        String[] parts = endpoint.split(":");
        if (parts.length != 2) return null;
        String host = parts[0].trim();
        int port;
        try { port = Integer.parseInt(parts[1].trim()); } catch (NumberFormatException ex) { return null; }
        for (var n : nodeState.getClusterConfig().getNodes()) {
            if (n.getHost().equals(host) && n.getGrpcPort() == port) return n;
        }
        return null;
    }

    private static String targetKey(ClusterConfig.NodeMetaData n) { return n.getHost() + ":" + n.getGrpcPort(); }


    public void sendClientReply(ClientReply reply) {
        String clientId = reply.getClientId();
        if (clientId == null || clientId.isBlank()) {
            log.warn("[{}] No clientId in reply → cannot route ClientReply", nodeState.getSelfNodeId());
            return;
        }

        if (!ENABLE_CLIENT_CALLBACK) {
            log.info("[{}] (log-only) ClientReply to {} → {}", nodeState.getSelfNodeId(), clientId, reply.getResult());
            return;
        }

        ManagedChannel channel = null;
        try {
            channel = ManagedChannelBuilder
                    .forAddress(CLIENT_CALLBACK_HOST, CLIENT_CALLBACK_PORT)
                    .usePlaintext()
                    .build();

            PbftServiceGrpc.PbftServiceBlockingStub stub =
                    PbftServiceGrpc.newBlockingStub(channel)
                            .withWaitForReady()
                            .withDeadlineAfter(10, TimeUnit.SECONDS); // safer if client is slow

            stub.onClientReply(reply);
            log.info("[{}] Sent ClientReply → {} ({})",
                    nodeState.getSelfNodeId(), clientId, reply.getResult());

        } catch (Exception e) {
        } finally {
            if (channel != null) {
                channel.shutdown();
                try {
                    channel.awaitTermination(CHANNEL_SHUTDOWN_MS, TimeUnit.MILLISECONDS);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }
}
