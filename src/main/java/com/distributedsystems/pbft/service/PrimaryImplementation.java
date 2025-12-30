package com.distributedsystems.pbft.service;

import com.distributedsystems.pbft.client.ReplicaClient;
import com.distributedsystems.pbft.model.DecrypterEntity;
import com.distributedsystems.pbft.model.EncrypterEntity;
import com.distributedsystems.pbft.model.ReplicaLogEntity;
import com.distributedsystems.pbft.persistence.ReplicaLogEntry;
import com.distributedsystems.pbft.proto.*;
import com.distributedsystems.pbft.repository.IEncrypterEntity;
import com.distributedsystems.pbft.repository.IDecrypterEntity;
import com.distributedsystems.pbft.state.NodeState;
import com.distributedsystems.pbft.service.ThresholdSignatureService;
import com.distributedsystems.pbft.service.ClientRequestAuthenticator;
import com.distributedsystems.pbft.service.PhaseHandlers.CommitPhaseHandlerImpl;
import com.distributedsystems.pbft.util.CryptoUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.JsonFormat;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

@Slf4j
@Service
@RequiredArgsConstructor
public class PrimaryImplementation {

    private final NodeState nodeState;
    private final ReplicaClient replicaClient;
    private final IEncrypterEntity privateRepo;
    private final IDecrypterEntity publicRepo;
    private final CryptoUtil crypto;
    private final ReplicaLogEntry replicaLogEntry;
    private final ExecutionServiceImpl executionService;
    private final ByzantineService byzantineService;
    private final CommitPhaseHandlerImpl commitHandler;
    private final ThresholdSignatureService thresholdSignatureService;
    private final ClientRequestAuthenticator clientRequestAuthenticator;

    @Value("${pbft.optimizations.bonus_1.enabled:false}")
    private boolean bonus1Enabled;

    @Value("${pbft.optimizations.bonus_1.max-wait-ms:40}")
    private long bonus1MaxWaitMs;

    private ScheduledExecutorService bonusScheduler;
    private final ConcurrentHashMap<Long, ScheduledFuture<?>> bonusFallbacks = new ConcurrentHashMap<>();
    private final AtomicBoolean bonus1FastPathDisabled = new AtomicBoolean(false);
    private volatile long bonus1DisabledView = -1L;

    @PostConstruct
    void initBonusScheduler() {
        if (bonus1Enabled) {
            ensureBonusScheduler();
        }
    }

    @PreDestroy
    void shutdownBonusScheduler() {
        if (bonusScheduler != null) {
            bonusScheduler.shutdownNow();
        }
    }

    @Transactional
    public PrePrepare onClientRequest(ClientRequest req) throws Exception {
        final String selfId = nodeState.getSelfNodeId();

        if (!nodeState.isParticipating()) {
            log.warn("[{}] Not in live set → rejecting client {}", selfId, req.getClientId());
            throw new IllegalStateException("LIVE_SET_IGNORE");
        }

        final long view = nodeState.getCurrentView();
        final String expectedLeader = nodeState.validPrimaryIdForView(view);
        if (!selfId.equals(expectedLeader)) {
            throw new IllegalStateException("Not primary for view " + view + " (expected " + expectedLeader + ")");
        }

        clientRequestAuthenticator.verify(req);

        String digest = crypto.sha256Base64Bytes(req.toByteArray());
        var existingPreOpt = nodeState.getPrePrepareLogMap().values().stream()
                .filter(p -> p.getDigest().equals(digest) && p.getView() == nodeState.getCurrentView())
                .findFirst();
        if (existingPreOpt.isPresent()) {
            PrePrepare existing = existingPreOpt.get();
            log.warn("[{}] Duplicate PRE-PREPARE for digest {} → reusing seq={} view={}",
                    selfId, digest, existing.getSequence(), existing.getView());
            return existing;
        }

        if (byzantineService != null) {
            byzantineService.maybeDelayPrimarySend(selfId, nodeState.isPrimary(), "PRE-PREPARE broadcast");
        }

        boolean equiv = byzantineService != null && byzantineService.isModeActive("equivocate") && byzantineService.isByzantine(selfId);
        long seq = allocateFreshSequence();
        long seq2 = -1L;
        if (equiv) {
            seq2 = allocateFreshSequence();
        }
        String reqJson = JsonFormat.printer().omittingInsignificantWhitespace().print(req);

        EncrypterEntity me = privateRepo.findById(selfId)
                .orElseThrow(() -> new IllegalStateException("Missing private key for " + selfId));
        PrivateKey priv = crypto.privateKeyFromBase64(me.getPrivateKey());

        String toSign = view + "|" + seq + "|" + digest + "|" + selfId;
        String sigB64 = crypto.signBase64(toSign, priv);
        sigB64 = byzantineService != null ? byzantineService.maybeCorruptSignature(selfId, sigB64) : sigB64;

        PrePrepare pre = PrePrepare.newBuilder()
                .setView(view)
                .setSequence(seq)
                .setDigest(digest)
                .setRequest(req)
                .setLeaderId(selfId)
                .setSignature(ByteString.copyFromUtf8(sigB64))
                .build();

        nodeState.putPrePrepare(pre);
        nodeState.markProgress();

        try {
            replicaLogEntry.upsert(
                    seq,
                    (int) view,
                    digest,
                    ReplicaLogEntity.Phase.PRE_PREPARE,
                    true,
                    reqJson,
                    digest,
                    reqJson
            );
            log.info("[{}] LOG PRE_PREPARE persisted seq={} view={} digest={}", selfId, seq, view, digest);
        } catch (Exception e) {
            log.error("[{}] LOG PRE_PREPARE persist failed seq={} → {}", selfId, seq, e.getMessage(), e);
            throw e;
        }

        if (equiv) {
            String sigB64b = crypto.signBase64(view + "|" + seq2 + "|" + digest + "|" + selfId, priv);
            sigB64b = byzantineService.maybeCorruptSignature(selfId, sigB64b);

            PrePrepare pre2 = PrePrepare.newBuilder()
                    .setView(view)
                    .setSequence(seq2)
                    .setDigest(digest)
                    .setRequest(req)
                    .setLeaderId(selfId)
                    .setSignature(ByteString.copyFromUtf8(sigB64b))
                    .build();

            nodeState.putPrePrepare(pre2);
            nodeState.markProgress();
            try {
                replicaLogEntry.upsert(seq2, (int) view, digest,
                        ReplicaLogEntity.Phase.PRE_PREPARE, true, reqJson, digest, reqJson);
            } catch (Exception e) {
                log.error("[{}] LOG PRE_PREPARE persist failed (equiv seq2={}) → {}", selfId, seq2, e.getMessage(), e);
            }

            var peers = nodeState.livePeersExcludingSelf();
            List<Integer> groupA = new ArrayList<>();
            List<Integer> groupB = new ArrayList<>();
            for (var p : peers) {
                String pid = "node-" + p.getId();

                if (byzantineService.isEquivocateVictim(pid)) {
                    replicaClient.sendPrePrepareToPeer(pre, p);
                    groupA.add(p.getId());
                } else {
                    replicaClient.sendPrePrepareToPeer(pre2, p);
                    groupB.add(p.getId());
                }
            }

            log.warn("[{}] EQUIVOCATE: sent seq={} (victims) to {}, seq={} (others) to {}",
                    selfId, seq, groupA, seq2, groupB);

        } else {
            replicaClient.broadcastPrePrepare(pre, nodeState.livePeersExcludingSelf());
            log.info("[{}] Broadcast PRE-PREPARE(seq={}, view={}, digest={}) to peers {}",
                    selfId, seq, view, digest,
                    nodeState.livePeersExcludingSelf().stream()
                            .map(p -> p.getHost() + ":" + p.getGrpcPort()).toList());
        }

        if (!nodeState.hasStarted()) {
            nodeState.markStarted();
        }

        return pre;
    }

    @Transactional
    public Acknowledge onPrepareFromBackup(Prepare p) {
        try {
            if (!nodeState.isParticipating()) {
                log.warn("[{}] Not in live set → ignoring PREPARE from {}", nodeState.getSelfNodeId(), p.getReplicaId());
                return ack(false, "LIVE_SET_IGNORE");
            }

            long seq = p.getSequence(), view = p.getView();
            String sender = p.getReplicaId(), digest = p.getDigest();

            PrePrepare pre = nodeState.getPrePrepareLog(seq)
                    .orElseThrow(() -> new IllegalStateException("No PrePrepare for seq=" + seq));

            if (pre.getView() != view || !pre.getDigest().equals(digest))
                return ack(false, "prepare mismatch");

            DecrypterEntity pubRow = publicRepo.findById(sender)
                    .orElseThrow(() -> new IllegalStateException("Unknown sender " + sender));
            PublicKey pub = crypto.publicKeyFromBase64(pubRow.getPublicKey());
            String msg = view + "|" + seq + "|" + digest + "|" + sender;

            if (!crypto.verifyBase64(msg, p.getSignature().toStringUtf8(), pub))
                return ack(false, "invalid prepare signature");

            nodeState.preparesFor(seq).add(p);
            if (thresholdSignatureService.isEnabled() && p.getThresholdShare() != null && !p.getThresholdShare().isEmpty()) {
                thresholdSignatureService.registerShare(
                        ThresholdSignatureService.SharePhase.PREPARE,
                        view, seq, digest, sender,
                        p.getThresholdShare().toByteArray());
            }
            nodeState.markActivity();
            int total = nodeState.preparesFor(seq).size();
            log.info("[{}] PREPARE accepted from {} (seq={}, total={})", nodeState.getSelfNodeId(), sender, seq, total);

            evaluatePrepareThreshold(seq, view, digest, pre);

            return ack(true, "prepare recorded");
        } catch (Exception e) {
            log.error("[{}] onPrepareFromBackup error: {}", nodeState.getSelfNodeId(), e.getMessage(), e);
            return ack(false, e.getMessage());
        }
    }

    @Transactional
    public Acknowledge onCommitFromBackup(Commit c) {
        try {
            if (!nodeState.isParticipating()) {
                log.warn("[{}] Not in live set → ignoring COMMIT from {}", nodeState.getSelfNodeId(), c.getReplicaId());
                return ack(false, "LIVE_SET_IGNORE");
            }

            long seq = c.getSequence(), view = c.getView();
            String sender = c.getReplicaId(), digest = c.getDigest();

            DecrypterEntity pubRow = publicRepo.findById(sender)
                    .orElseThrow(() -> new IllegalStateException("Unknown sender " + sender));
            PublicKey pub = crypto.publicKeyFromBase64(pubRow.getPublicKey());
            String msg = view + "|" + seq + "|" + digest + "|" + sender;

            if (!crypto.verifyBase64(msg, c.getSignature().toStringUtf8(), pub))
                return ack(false, "invalid commit signature");

            nodeState.commitsFor(seq).add(c);
            if (thresholdSignatureService.isEnabled() && c.getThresholdShare() != null && !c.getThresholdShare().isEmpty()) {
                thresholdSignatureService.registerShare(
                        ThresholdSignatureService.SharePhase.COMMIT,
                        view, seq, digest, sender,
                        c.getThresholdShare().toByteArray());
            }
            nodeState.markActivity();
            int total = nodeState.commitsFor(seq).size();
            log.info("[{}] COMMIT accepted from {} (seq={}, total={})",
                    nodeState.getSelfNodeId(), sender, seq, total);

            if (total >= nodeState.quorumSize() && !hasUpToDateCommitCertificate(seq, view, digest)) {
                CommitCertificate cert = buildSignedCommitCertificate(view, seq, digest);
                CommitCertificate existing = nodeState.getCommitCertificates().put(seq, cert);
                if (existing != null && existing.getView() != cert.getView()) {
                    log.warn("[{}] Replacing CommitCertificate(seq={}) view {} → {}",
                            nodeState.getSelfNodeId(), seq, existing.getView(), cert.getView());
                }

                try {
                    var pre = nodeState.getPrePrepareLog(seq).orElse(null);
                    String reqJson = pre != null
                            ? JsonFormat.printer().omittingInsignificantWhitespace().print(pre.getRequest())
                            : null;
                    replicaLogEntry.upsert(seq, (int) view, digest,
                            ReplicaLogEntity.Phase.COMMITTED, true, reqJson,
                            pre != null ? pre.getDigest() : null,
                            reqJson);
                } catch (Exception e) {
                    log.warn("[{}] LOG COMMITTED persist failed seq={} (continuing PBFT): {}",
                            nodeState.getSelfNodeId(), seq, e.getMessage());
                }

                if (byzantineService != null) {
                    byzantineService.maybeDelayPrimarySend(selfId(), nodeState.isPrimary(),
                            "CommitCertificate broadcast");
                }

                replicaClient.broadcastCommitCertificate(cert, nodeState.livePeersExcludingSelf());
                log.info("[{}] Broadcast CommitCertificate(seq={}, commits={})",
                        nodeState.getSelfNodeId(), seq, cert.getCommitsCount());

                execute(seq);
            }

            return ack(true, "commit recorded");
        } catch (Exception e) {
            log.error("[{}] onCommitFromBackup error: {}", nodeState.getSelfNodeId(), e.getMessage(), e);
            return ack(false, e.getMessage());
        }
    }

    private void execute(long seq) {
        try {
            nodeState.getPrePrepareLog(seq).ifPresent(pre -> {
                var reply = executionService.execute(seq);
                log.info("[{}] EXECUTE seq={} op='{}' client={} → status={}",
                        nodeState.getSelfNodeId(),
                        seq,
                        pre.getRequest().getOperation(),
                        pre.getRequest().getClientId(),
                        reply.getResult());
            });
        } catch (Exception e) {
            log.error("[{}] execute(seq={}) failed: {}", nodeState.getSelfNodeId(), seq, e.getMessage(), e);
        }
    }

    private boolean isFastPathAllowed(long view) {
        if (!bonus1Enabled) return false;
        if (!bonus1FastPathDisabled.get()) return true;
        if (view > bonus1DisabledView) {
            if (bonus1FastPathDisabled.compareAndSet(true, false)) {
                log.info("[{}] bonus_1 fast path re-enabled for view {}", nodeState.getSelfNodeId(), view);
            }
            return true;
        }
        return false;
    }

    private void disableBonusFastPath(long view, String reason) {
        if (!bonus1Enabled) return;
        bonus1DisabledView = Math.max(bonus1DisabledView, view);
        if (bonus1FastPathDisabled.compareAndSet(false, true)) {
            log.warn("[{}] bonus_1 fast path disabled for view {} ({}). Falling back to classic COMMIT flow.",
                    nodeState.getSelfNodeId(), view, reason);
        }
    }

    public void resetBonusFastPath() {
        if (!bonus1Enabled) return;
        bonus1DisabledView = -1L;
        if (bonus1FastPathDisabled.compareAndSet(true, false)) {
            log.info("[{}] bonus_1 fast path reset after administrative flush", nodeState.getSelfNodeId());
        }
    }

    public void suspendBonusFastPath(String reason) {
        if (!bonus1Enabled) return;
        String note = (reason == null || reason.isBlank()) ? "manual suspension" : reason;
        disableBonusFastPath(nodeState.getCurrentView(), note);
    }

    private void evaluatePrepareThreshold(long seq, long view, String digest, PrePrepare pre) throws Exception {
        if (isSelfCrashed()) {
            log.debug("[{}] Crash attack → ignoring PREPARE quorum for seq={} view={}",
                    selfId(), seq, view);
            return;
        }
        if (hasUpToDatePrepareCertificate(seq, view, digest)) return;

        int collected = nodeState.preparesFor(seq).size();
        if (!bonus1Enabled) {
            if (collected >= nodeState.getBackupAckCount()) {
                broadcastPrepareCertificate(seq, view, digest, pre, false, "2f quorum reached");
            }
            return;
        }

        if (!isFastPathAllowed(view)) {
            if (collected >= nodeState.getBackupAckCount()) {
                broadcastPrepareCertificate(seq, view, digest, pre, false,
                        "bonus_1 suspended for view " + view);
            }
            return;
        }

        Set<Integer> liveRoster = nodeState.getLiveNodes();
        int liveCount = (liveRoster == null || liveRoster.isEmpty())
                ? nodeState.totalNodes()
                : liveRoster.size();
        int allBackups = Math.max(0, Math.min(nodeState.totalNodes(), liveCount) - 1);
        boolean hasAllPrepares = allBackups == 0 ? collected > 0 : collected >= allBackups;

        if (hasAllPrepares) {
            log.info("[{}] bonus_1 fast path → collected {} prepares (need all {}) for seq={}",
                    nodeState.getSelfNodeId(), collected, allBackups, seq);
            cancelBonusFallback(seq);
            broadcastPrepareCertificate(seq, view, digest, pre, true, "all prepares collected");
            return;
        }

        if (collected >= nodeState.getBackupAckCount()) {
            scheduleBonusFallback(seq, view, digest, pre);
        }
    }

    private void scheduleBonusFallback(long seq, long view, String digest, PrePrepare pre) throws Exception {
        if (isSelfCrashed()) {
            log.debug("[{}] Crash attack → not scheduling bonus fallback for seq={} view={}",
                    selfId(), seq, view);
            return;
        }
        if (hasUpToDatePrepareCertificate(seq, view, digest)) return;

        if (bonus1MaxWaitMs <= 0) {
            log.debug("[{}] bonus_1 max-wait <= 0 → immediate fallback for seq={}", nodeState.getSelfNodeId(), seq);
            broadcastPrepareCertificate(seq, view, digest, pre, false, "bonus_1 immediate fallback");
            return;
        }

        if (ensureBonusScheduler() == null) {
            log.warn("[{}] bonus_1 scheduler unavailable → fallback immediately for seq={}",
                    nodeState.getSelfNodeId(), seq);
            broadcastPrepareCertificate(seq, view, digest, pre, false, "bonus_1 scheduler-missing");
            return;
        }

        bonusFallbacks.computeIfAbsent(seq, key -> {
            log.info("[{}] bonus_1 waiting up to {} ms for full prepare set at seq={}",
                    nodeState.getSelfNodeId(), bonus1MaxWaitMs, seq);
            return bonusScheduler.schedule(() -> {
                try {
                    if (hasUpToDatePrepareCertificate(seq, view, digest)) return;
                    log.info("[{}] bonus_1 fallback firing for seq={} after {} ms",
                            nodeState.getSelfNodeId(), seq, bonus1MaxWaitMs);
                    disableBonusFastPath(view, "timeout while waiting for all prepares");
                    broadcastPrepareCertificate(seq, view, digest, pre, false, "bonus_1 fallback timer");
                } catch (Exception e) {
                    log.error("[{}] bonus_1 fallback failed for seq={}: {}", nodeState.getSelfNodeId(),
                            seq, e.getMessage(), e);
                } finally {
                    bonusFallbacks.remove(seq);
                }
            }, bonus1MaxWaitMs, TimeUnit.MILLISECONDS);
        });
    }

    private void cancelBonusFallback(long seq) {
        ScheduledFuture<?> future = bonusFallbacks.remove(seq);
        if (future != null) {
            future.cancel(false);
        }
    }

    private void broadcastPrepareCertificate(long seq, long view, String digest, PrePrepare pre,
                                              boolean fastPath, String reason) throws Exception {
        if (isSelfCrashed()) {
            log.warn("[{}] Crash attack → suppressing PrepareCertificate for seq={} view={} ({})",
                    selfId(), seq, view, reason);
            return;
        }
        if (hasUpToDatePrepareCertificate(seq, view, digest)) return;
        cancelBonusFallback(seq);

        PrepareCertificate cert = buildSignedPrepareCertificate(view, seq, digest);
        PrepareCertificate existing = nodeState.getPrepareCertificates().put(seq, cert);
        if (existing != null && existing.getView() != cert.getView()) {
            log.warn("[{}] Replacing PrepareCertificate(seq={}) view {} → {}",
                    nodeState.getSelfNodeId(), seq, existing.getView(), cert.getView());
        }

        try {
            String reqJson = JsonFormat.printer().omittingInsignificantWhitespace().print(pre.getRequest());
            replicaLogEntry.upsert(seq, (int) view, digest,
                    ReplicaLogEntity.Phase.PREPARED, true, reqJson, pre.getDigest(), reqJson);
        } catch (Exception e) {
            log.warn("[{}] LOG PREPARED persist failed seq={} (continuing PBFT): {}",
                    nodeState.getSelfNodeId(), seq, e.getMessage());
        }

        if (byzantineService != null) {
            byzantineService.maybeDelayPrimarySend(selfId(), nodeState.isPrimary(),
                    "PrepareCertificate broadcast");
        }

        String mode = fastPath ? "bonus_1-fast" : "normal";
        log.info("[{}] Broadcast PrepareCertificate(seq={}, prepares={}, mode={}, reason={})",
                nodeState.getSelfNodeId(), seq, cert.getPreparesCount(), mode, reason);
        replicaClient.broadcastPrepareCertificate(cert, nodeState.livePeersExcludingSelf());

        Commit myCommit = buildSignedCommit(view, seq, digest, selfId());
        commitHandler.onCommitFromBackup(myCommit);
    }

    private ScheduledExecutorService ensureBonusScheduler() {
        if (!bonus1Enabled) {
            return null;
        }
        if (bonusScheduler == null) {
            ThreadFactory tf = r -> {
                Thread t = new Thread(r, "pbft-bonus1");
                t.setDaemon(true);
                return t;
            };
            bonusScheduler = Executors.newSingleThreadScheduledExecutor(tf);
        }
        return bonusScheduler;
    }

    private PrepareCertificate buildSignedPrepareCertificate(long view, long seq, String digest) throws Exception {
        final String selfId = selfId();
        EncrypterEntity me = privateRepo.findById(selfId)
                .orElseThrow(() -> new IllegalStateException("Missing private key " + selfId));
        PrivateKey priv = crypto.privateKeyFromBase64(me.getPrivateKey());

        String msg = view + "|" + seq + "|" + digest + "|" + selfId;
        String sigB64 = crypto.signBase64(msg, priv);
        sigB64 = byzantineService != null ? byzantineService.maybeCorruptSignature(selfId, sigB64) : sigB64;

        PrepareCertificate cert = PrepareCertificate.newBuilder()
                .setView(view).setSequence(seq).setDigest(digest)
                .setLeaderId(selfId)
                .setLeaderSignature(ByteString.copyFromUtf8(sigB64))
                .addAllPrepares(nodeState.preparesFor(seq))
                .build();
        return thresholdSignatureService.tryAggregate(
                        ThresholdSignatureService.SharePhase.PREPARE, view, seq, digest)
                .map(bytes -> cert.toBuilder()
                        .clearPrepares()
                        .setThresholdMode(true)
                        .setThresholdSignature(ByteString.copyFrom(bytes))
                        .build())
                .orElse(cert);
    }

    private Commit buildSignedCommit(long view, long seq, String digest, String replicaId) throws Exception {
        EncrypterEntity me = privateRepo.findById(replicaId)
                .orElseThrow(() -> new IllegalStateException("Missing private key " + replicaId));
        PrivateKey priv = crypto.privateKeyFromBase64(me.getPrivateKey());

        String msg = view + "|" + seq + "|" + digest + "|" + replicaId;
        String sigB64 = crypto.signBase64(msg, priv);
        sigB64 = byzantineService != null ? byzantineService.maybeCorruptSignature(replicaId, sigB64) : sigB64;

        Commit.Builder builder = Commit.newBuilder()
                .setView(view).setSequence(seq).setDigest(digest)
                .setReplicaId(replicaId)
                .setSignature(ByteString.copyFromUtf8(sigB64));

        thresholdSignatureService.createPartialSignature(
                        ThresholdSignatureService.SharePhase.COMMIT,
                        view, seq, digest, replicaId)
                .ifPresent(bytes -> builder.setThresholdShare(ByteString.copyFrom(bytes)));

        return builder.build();
    }

    private CommitCertificate buildSignedCommitCertificate(long view, long seq, String digest) throws Exception {
        final String selfId = selfId();
        EncrypterEntity me = privateRepo.findById(selfId)
                .orElseThrow(() -> new IllegalStateException("Missing private key " + selfId));
        PrivateKey priv = crypto.privateKeyFromBase64(me.getPrivateKey());

        String msg = view + "|" + seq + "|" + digest + "|" + selfId;
        String sigB64 = crypto.signBase64(msg, priv);
        sigB64 = byzantineService != null ? byzantineService.maybeCorruptSignature(selfId, sigB64) : sigB64;

        CommitCertificate cert = CommitCertificate.newBuilder()
                .setView(view).setSequence(seq).setDigest(digest)
                .setLeaderId(selfId)
                .setLeaderSignature(ByteString.copyFromUtf8(sigB64))
                .addAllCommits(nodeState.commitsFor(seq))
                .build();

        return thresholdSignatureService.tryAggregate(
                        ThresholdSignatureService.SharePhase.COMMIT, view, seq, digest)
                .map(bytes -> cert.toBuilder()
                        .clearCommits()
                        .setThresholdMode(true)
                        .setThresholdSignature(ByteString.copyFrom(bytes))
                        .build())
                .orElse(cert);
    }

    private boolean hasUpToDatePrepareCertificate(long seq, long view, String digest) {
        PrepareCertificate existing = nodeState.getPrepareCertificates().get(seq);
        if (existing == null) return false;
        if (existing.getView() > view) return true;
        return existing.getView() == view && Objects.equals(existing.getDigest(), digest);
    }

    private boolean hasUpToDateCommitCertificate(long seq, long view, String digest) {
        CommitCertificate existing = nodeState.getCommitCertificates().get(seq);
        if (existing == null) return false;
        if (existing.getView() > view) return true;
        return existing.getView() == view && Objects.equals(existing.getDigest(), digest);
    }

    private Acknowledge ack(boolean ok, String msg) {
        return Acknowledge.newBuilder().setSuccess(ok).setMessage(msg).build();
    }

    private String selfId() {
        return nodeState.getSelfNodeId();
    }

    private boolean isSelfCrashed() {
        return byzantineService != null && byzantineService.isCrashed(selfId());
    }

    private long allocateFreshSequence() {
        long floor = Math.max(
                Math.max(nodeState.getLastCommitSequenceNumber(), nodeState.getLastExecutedSequenceNumber()),
                nodeState.getLowWatermark());
        long seq;
        synchronized (nodeState) {
            seq = nodeState.nextSequence();
            while (seq <= floor || nodeState.getPrePrepareLog(seq).isPresent()) {
                long newFloor = Math.max(floor, seq);
                nodeState.setNextSequence(newFloor + 1);
                seq = nodeState.nextSequence();
                floor = Math.max(newFloor, Math.max(nodeState.getLastCommitSequenceNumber(),
                        nodeState.getLastExecutedSequenceNumber()));
                floor = Math.max(floor, nodeState.getLowWatermark());
            }
        }
        return seq;
    }
}
