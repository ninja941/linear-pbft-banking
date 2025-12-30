package com.distributedsystems.pbft.service.PhaseHandlers;

import com.distributedsystems.pbft.client.ReplicaClient;
import com.distributedsystems.pbft.persistence.KeyManager;
import com.distributedsystems.pbft.persistence.ReplicaLogEntry;
import com.distributedsystems.pbft.model.ReplicaLogEntity;
import com.distributedsystems.pbft.proto.CheckpointCertificate;
import com.distributedsystems.pbft.proto.CheckpointProof;
import com.distributedsystems.pbft.proto.CheckpointSummary;
import com.distributedsystems.pbft.proto.ClientRequest;
import com.distributedsystems.pbft.proto.CommitCertificate;
import com.distributedsystems.pbft.proto.Acknowledge;
import com.distributedsystems.pbft.proto.NewView;
import com.distributedsystems.pbft.proto.PrePrepare;
import com.distributedsystems.pbft.proto.PreparedEntry;
import com.distributedsystems.pbft.proto.ViewChange;
import com.distributedsystems.pbft.repository.ICheckpointRepository;
import com.distributedsystems.pbft.repository.IReplicatLogRepository;
import com.distributedsystems.pbft.service.CheckpointService;
import com.distributedsystems.pbft.service.ByzantineService;
import com.distributedsystems.pbft.state.NodeState;
import com.distributedsystems.pbft.util.CryptoUtil;
import com.distributedsystems.pbft.util.ByzantineInterceptor;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.JsonFormat;
import com.google.protobuf.TextFormat;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.stream.Collectors;

import static com.distributedsystems.pbft.util.ViewChangeCodec.*;

@Slf4j
@Service
public class ViewChangePhaseHandlerImpl {

    private final NodeState nodeState;
    private final CryptoUtil cryptoUtil;
    private final KeyManager keyManager;
    private final ICheckpointRepository checkpointRepo;
    private final CheckpointService checkpointService;
    private final ByzantineService byzantineService;
    private final IReplicatLogRepository logRepo;
    private final ReplicaLogEntry replicaLogEntry;

    @Value("${pbft.timers.activity-timeout-ms:3000}")
    private long activityTimeoutMs;
    @Value("${pbft.timers.progress-timeout-ms:8000}")
    private long progressTimeoutMs;

    @Value("${pbft.timers.startup-grace-ms:5000}")
    private long startupGraceMs;

    @Value("${pbft.timers.check-interval-ms:1000}")
    private long checkIntervalMs;
    @Value("${pbft.timers.view-change-timeout-ms:2000}")
    private long viewChangeTimeoutMs;

    private final AtomicLong lastInitiatedView = new AtomicLong(-1);
    private final AtomicBoolean viewChangePending = new AtomicBoolean(false);
    private final AtomicLong viewChangeStartMs = new AtomicLong(0);
    private final AtomicLong pendingViewTarget = new AtomicLong(-1);
    private final AtomicInteger viewChangeBackoffExp = new AtomicInteger(0);
    private final AtomicBoolean viewChangeTimerArmed = new AtomicBoolean(false);
    private final NavigableSet<Long> trackedViewNumbers = new ConcurrentSkipListSet<>();
    private static final int MAX_BACKOFF_SHIFT = 5;
    private final AtomicLong lastViewInstallMs = new AtomicLong(System.currentTimeMillis());
    private final AtomicLong smallestHigherViewHint = new AtomicLong(-1);
    private final AtomicLong executionBaselineSeq = new AtomicLong(0);

    private NewViewPhaseHandlerImpl newViewPhaseHandler;
    private ReplicaClient replicaClient;

    @Autowired private ByzantineInterceptor interceptor;

    @Autowired
    public ViewChangePhaseHandlerImpl(
            NodeState nodeState,
            CryptoUtil cryptoUtil,
            KeyManager keyManager,
            ICheckpointRepository checkpointRepository,
            CheckpointService checkpointService,
            ByzantineService byzantineService,
            IReplicatLogRepository logRepo,
            ReplicaLogEntry replicaLogEntry
    ) {
        this.nodeState = nodeState;
        this.cryptoUtil = cryptoUtil;
        this.keyManager = keyManager;
        this.checkpointRepo = checkpointRepository;
        this.checkpointService = checkpointService;
        this.byzantineService = byzantineService;
        this.logRepo = logRepo;
        this.replicaLogEntry = replicaLogEntry;
    }

    private PreparedEntry buildPreparedEntry(long seq, long view, String digest,
                                             String payloadSummary,
                                             String payloadJson) {
        String normalizedDigest = Optional.ofNullable(digest).orElse("");
        String descriptor = inferClientDescriptor(seq, payloadSummary, payloadJson);

        return PreparedEntry.newBuilder()
                .setSequence(seq)
                .setView(view)
                .setDigest(normalizedDigest)
                .setClientId(descriptor)
                .build();
    }

    private String inferClientDescriptor(long seq, String payloadSummary, String payloadJson) {
        return nodeState.getPrePrepareLog(seq)
                .map(pre -> serializeRequest(pre.getRequest()))
                .filter(s -> !s.isBlank())
                .orElseGet(() -> {
                    String fromJson = parseClientRequestJson(payloadJson);
                    if (!fromJson.isBlank()) return fromJson;
                    return Optional.ofNullable(payloadSummary).orElse("");
                });
    }

    private String serializeRequest(ClientRequest req) {
        if (req == null) return "";
        try {
            return JsonFormat.printer().omittingInsignificantWhitespace().print(req);
        } catch (Exception e) {
            return req.toString();
        }
    }

    private String parseClientRequestJson(String json) {
        if (json == null || json.isBlank()) return "";
        try {
            ClientRequest.Builder builder = ClientRequest.newBuilder();
            JsonFormat.parser().ignoringUnknownFields().merge(json, builder);
            return JsonFormat.printer().omittingInsignificantWhitespace().print(builder);
        } catch (Exception ignored) {
            try {
                ClientRequest.Builder builder = ClientRequest.newBuilder();
                TextFormat.getParser().merge(json, builder);
                return JsonFormat.printer().omittingInsignificantWhitespace().print(builder);
            } catch (Exception ignoredAgain) {
                return "";
            }
        }
    }

    @Autowired @Lazy
    public void setReplicaClient(ReplicaClient replicaClient) { this.replicaClient = replicaClient; }

    @Autowired @Lazy
    public void setNewViewPhaseHandler(NewViewPhaseHandlerImpl handler) { this.newViewPhaseHandler = handler; }

    @PostConstruct
    void register() {
        nodeState.setViewChangeHandler(this);
        executionBaselineSeq.set(nodeState.getLastExecutedSequenceNumber());
        log.info("[{}] ViewChangePhaseHandlerImpl registered", nodeState.getSelfNodeId());
    }

    @PreDestroy
    public void shutdown() {
        viewChangePending.set(false);
    }

    public void resetForFlush() {
        try {
            viewChangePending.set(false);
            lastInitiatedView.set(-1);
            pendingViewTarget.set(-1);
            viewChangeStartMs.set(0L);
            viewChangeTimerArmed.set(false);
            clearHigherViewEvidence();
            executionBaselineSeq.set(nodeState.getLastExecutedSequenceNumber());
            log.debug("[{}] ViewChange handler reset after flush", nodeState.getSelfNodeId());
        } catch (Exception ignored) { }
    }

    @Scheduled(fixedDelayString = "${pbft.timers.check-interval-ms:1000}")
    public void monitorProgress() {
        try {
            final long now = System.currentTimeMillis();

            if (!nodeState.isParticipating()) {
                viewChangePending.set(false);
                pendingViewTarget.set(-1);
                return;
            }

            if (!nodeState.hasStarted()) {
                viewChangePending.set(false);
                pendingViewTarget.set(-1);
                return;
            }

            flushHigherViewEvidenceAfterExecution();

            boolean withinGrace = now - nodeState.getStartedAtMs() < startupGraceMs;
            if (withinGrace && !viewChangePending.get() && !nodeState.hasProcessedRequests()) {
                return;
            }

            boolean outstanding = nodeState.hasOutstandingProgress();
            boolean everProcessed = nodeState.hasProcessedRequests();

            if (viewChangePending.get()) {
            } else if (!outstanding) {
                if (!everProcessed) {
                    return;
                }
                return;
            }

            if (byzantineService.isCrashed(nodeState.getSelfNodeId())) return;

            final long sinceProgress = now - nodeState.getLastProgressTimestamp();
            final long sinceActivity = now - nodeState.getLastActivityTimestamp();

            if (!nodeState.isPrimary()) {
                if (nodeState.hasProcessedRequests() && !nodeState.hasOutstandingProgress()) {
                    viewChangePending.set(false);
                    pendingViewTarget.set(-1);
                    return;
                }
                if (sinceActivity > activityTimeoutMs) {
                    requestViewChange("No progress from primary for " + sinceActivity + " ms");
                }
            } else {
                if (sinceProgress > progressTimeoutMs) {
                    requestViewChange("No commit/phase progress for " + sinceProgress + " ms (primary)");
                }
            }

            if (viewChangePending.get()) {
                if (viewChangeTimerArmed.get()) {
                    long started = viewChangeStartMs.get();
                    long target = pendingViewTarget.get();
                    long elapsed = started > 0 ? now - started : 0L;
                    if (viewChangeTimeoutMs > 0 && target >= 0 && started > 0) {
                        long effectiveTimeout = effectiveTimeoutMs();
                        if (elapsed >= effectiveTimeout) {
                            if (nodeState.getCurrentView() >= target) {
                                viewChangePending.set(false);
                                viewChangeTimerArmed.set(false);
                                pendingViewTarget.set(-1);
                                viewChangeStartMs.set(0L);
                                resetViewChangeBackoff();
                            } else {
                                long hint = smallestHigherViewHint.getAndSet(-1L);
                                long nextView = Math.max(nodeState.getCurrentView() + 1, target + 1);
                                if (hint > target && hasRemoteQuorum(hint, nodeState.getByzantineNodesCount() + 1)) {
                                    nextView = hint;
                                }
                                viewChangePending.set(false);
                                viewChangeTimerArmed.set(false);
                                pendingViewTarget.set(-1);
                                viewChangeStartMs.set(0L);
                                viewChangeBackoffExp.updateAndGet(exp -> Math.min(exp + 1, MAX_BACKOFF_SHIFT));
                                log.warn("[{}] Escalating view-change to view {} after {} ms without NEW-VIEW "
                                                + "(next timeout {} ms)",
                                        nodeState.getSelfNodeId(), nextView, elapsed, effectiveTimeoutMs());
                                requestViewChange(nextView, "Escalation after " + elapsed + " ms", true);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error("[{}] monitorProgress error: {}", nodeState.getSelfNodeId(), e.getMessage(), e);
        }
    }

    public Acknowledge onViewChange(ViewChange req) {
        try {
            if (!nodeState.isParticipating()) {
                log.debug("[{}] Ignoring VIEW-CHANGE(newView={}) while not participating",
                        nodeState.getSelfNodeId(), req.getNewView());
                return fail("LIVE_SET_IGNORE");
            }
            if (!verifyViewChange(req)) return fail("Invalid ViewChange signature");
            recordViewChange(req);
            long requestedView = req.getNewView();
            boolean selfCrashed = byzantineService.isCrashed(nodeState.getSelfNodeId());

            if (!selfCrashed
                    && requestedView > nodeState.getCurrentView()
                    && !nodeState.isViewChangeInProgress(requestedView)) {
                log.debug("[{}] Recorded remote VIEW-CHANGE for view {} from {} (local view={})",
                        nodeState.getSelfNodeId(), requestedView, req.getReplicaId(), nodeState.getCurrentView());
            }

            String expectedLeader = nodeState.validPrimaryIdForView((int) requestedView);
            if (!selfCrashed
                    && expectedLeader != null
                    && byzantineService.isCrashed(expectedLeader)
                    && requestedView >= nodeState.getCurrentView()) {
                log.debug("[{}] VIEW-CHANGE indicates crashed leader {} for view {} → waiting for quorum",
                        nodeState.getSelfNodeId(), expectedLeader, requestedView);
            }
            maybeStartNewView((int) req.getNewView());
            return success("ViewChange recorded");
        } catch (Exception e) {
            log.error("[{}] onViewChange error: {}", nodeState.getSelfNodeId(), e.getMessage(), e);
            return fail(e.getMessage());
        }
    }

    public void requestViewChange(String reason) {
        long targetView = nodeState.getCurrentView() + 1;
        requestViewChange(targetView, reason, false);
    }

    public void requestViewChange(long targetView, String reason) {
        requestViewChange(targetView, reason, false);
    }

    private void requestViewChange(long targetView, String reason, boolean force) {
        if (!nodeState.isParticipating()) {
            log.debug("[{}] Skipping view-change request for view {} ({}); not participating",
                    nodeState.getSelfNodeId(), targetView, reason);
            return;
        }
        if (byzantineService.isCrashed(nodeState.getSelfNodeId())) {
            log.debug("[{}] Skipping view-change request for view {} ({}); crash attack active",
                    nodeState.getSelfNodeId(), targetView, reason);
            return;
        }
        if (!nodeState.tryStartViewChange(targetView)) return;
        pendingViewTarget.set(targetView);
        viewChangePending.set(true);
        viewChangeTimerArmed.set(false);
        if (!force) {
            viewChangeBackoffExp.set(0);
        }
        initiateLocalViewChange(targetView, reason);
        maybeArmViewChangeTimer(targetView);
    }

    public synchronized void initiateLocalViewChange(long targetView, String reason) {
        if (targetView <= nodeState.getCurrentView()) return;
        if (lastInitiatedView.get() >= targetView) return;

        try {
            ViewChange local = buildLocalViewChange(targetView);
            recordViewChange(local);

            if (!interceptor.shouldBlock("view-change")) {
                replicaClient.broadcastViewChange(local, nodeState.livePeersExcludingSelf());
            }

            lastInitiatedView.set(targetView);
            log.warn("[{}] Initiated ViewChange → view={} ({})",
                    nodeState.getSelfNodeId(), targetView, reason);
        } catch (Exception e) {
            log.error("[{}] Failed to initiate ViewChange {}: {}", nodeState.getSelfNodeId(), targetView, e.getMessage());
        }
    }

    private void recordViewChange(ViewChange req) {
        nodeState.viewChangesFor(req.getNewView()).put(req.getReplicaId(), req);
        trackedViewNumbers.add(req.getNewView());
        maybeArmViewChangeTimer(req.getNewView());
        maybeRecordHigherViewHint(req.getNewView());
        maybeFollowHigherViewQuorum();
    }

    private void maybeStartNewView(int candidateView) throws Exception {
        String self = nodeState.getSelfNodeId();
        String expectedLeader = nodeState.validPrimaryIdForView(candidateView);

        if (!nodeState.isParticipating()) {
            log.debug("[{}] Skipping NEW-VIEW assembly for view {} (spectator)", self, candidateView);
            return;
        }

        if (!expectedLeader.equals(self)) return; // only leader starts
        if (byzantineService.isCrashed(self)) {
            log.debug("[{}] Crash attack → refusing to assemble NEW-VIEW {}", self, candidateView);
            return;
        }

        Map<String, ViewChange> collected = nodeState.viewChangesFor(candidateView);
        if (collected.size() < nodeState.quorumSize()) return;

        nodeState.updateLeader(expectedLeader);
        nodeState.markProgress();

        NewView newViewMsg = buildNewViewMessage(candidateView, collected.values());
        if (!interceptor.shouldBlock("new-view")) {
            replicaClient.broadcastNewView(newViewMsg, nodeState.livePeersExcludingSelf());
        }

        newViewPhaseHandler.onNewView(newViewMsg);

        nodeState.installView(candidateView);
        nodeState.clearViewChanges(candidateView);
        onNewViewInstalled(candidateView);

        log.info("[{}] Installed NEW-VIEW={} (I am primary)", self, candidateView);
    }

    private boolean verifyViewChange(ViewChange req) throws Exception {
        PublicKey pubKey = keyManager.publicKeyOf(req.getReplicaId());
        String digest = preparedEntriesDigest(req.getPreparedMessagesList());
        String checkpointPart = checkpointDigest(req.hasCheckpoint() ? req.getCheckpoint() : null);
        String message = req.getNewView() + "|" + req.getReplicaId() + "|" + checkpointPart + "|" + digest;
        return cryptoUtil.verifyBase64(message, req.getSignature(), pubKey);
    }

    private List<PreparedEntry> collectOutstandingPreparedEntries() {
        long checkpointSeq = Math.max(nodeState.getLastCheckpointSequenceNumber(), nodeState.getLowWatermark());
        Map<Long, PreparedEntry> prepared = new HashMap<>();

        nodeState.getCommitCertificates().forEach((seq, cert) -> {
            if (seq <= checkpointSeq) return;
            Optional<String> payloadJson = resolvePrePreparePayload(seq);
            if (payloadJson.isEmpty()) {
                log.debug("[{}] Skipping prepared entry for seq={} (commit certificate but no PRE-PREPARE payload)",
                        nodeState.getSelfNodeId(), seq);
                return;
            }
            prepared.put(seq, buildPreparedEntry(seq, cert.getView(), cert.getDigest(), null, payloadJson.get()));
        });

        nodeState.getPrePrepareLogMap().forEach((seq, pre) -> {
            if (seq <= checkpointSeq) return;
            boolean committed = nodeState.getCommitCertificates().containsKey(seq) ||
                    nodeState.commitsFor(seq).size() >= nodeState.getBackupAckCount();
            boolean preparedLocally = nodeState.preparesFor(seq).size() >= nodeState.getBackupAckCount();
            if (preparedLocally || committed) {
                prepared.putIfAbsent(seq, buildPreparedEntry(seq, pre.getView(), pre.getDigest(), null,
                        serializeRequest(pre.getRequest())));
            }
        });

        logRepo.findAll().stream()
                .filter(row -> row.getSequenceNumber() > checkpointSeq
                        && row.getPrePrepareDigest() != null
                        && row.getPrePreparePayload() != null
                        && !row.getPrePreparePayload().isBlank()
                        && row.getPhase() != null
                        && row.getPhase().ordinal() >= ReplicaLogEntity.Phase.PREPARED.ordinal())
                .forEach(row -> prepared.putIfAbsent(
                        row.getSequenceNumber(),
                        buildPreparedEntry(
                                row.getSequenceNumber(),
                                row.getViewNumber(),
                                row.getPrePrepareDigest(),
                                row.getPayload(),
                                row.getPrePreparePayload())));

        return prepared.values().stream()
                .sorted(Comparator.comparingLong(PreparedEntry::getSequence))
                .collect(Collectors.toList());
    }

    private Optional<String> resolvePrePreparePayload(long seq) {
        Optional<String> inMemory = nodeState.getPrePrepareLog(seq)
                .map(PrePrepare::getRequest)
                .map(this::serializeRequest)
                .filter(s -> !s.isBlank());
        if (inMemory.isPresent()) return inMemory;

        return logRepo.findById(seq)
                .map(ReplicaLogEntity::getPrePreparePayload)
                .filter(Objects::nonNull)
                .filter(s -> !s.isBlank());
    }

    private ViewChange buildLocalViewChange(long targetView) throws Exception {
        String replicaId = nodeState.getSelfNodeId();
        List<PreparedEntry> preparedEntries = collectOutstandingPreparedEntries();
        CheckpointCertificate certificate = checkpointService.loadBestValidCertificate().orElse(null);
        CheckpointSummary checkpointSummary = checkpointService.loadLatestCheckpointSummary()
                .filter(summary -> certificate == null || summary.getSequence() == certificate.getSequence())
                .map(summary -> CheckpointSummary.newBuilder(summary).build())
                .orElse(null);

        if (checkpointSummary == null && certificate != null) {
            checkpointSummary = CheckpointSummary.newBuilder()
                    .setSequence(certificate.getSequence())
                    .setDigest(certificate.getDigest())
                    .setLabel("CERT")
                    .build();
        }

        if (checkpointSummary != null && checkpointSummary.getLabel().isBlank()) {
            checkpointSummary = CheckpointSummary.newBuilder(checkpointSummary)
                    .setLabel("CHECKPOINT_SEQ_" + checkpointSummary.getSequence())
                    .build();
        }

        String digest = preparedEntriesDigest(preparedEntries);
        String checkpointPart = checkpointSummary != null ? checkpointDigest(checkpointSummary) : "";
        String payload = targetView + "|" + replicaId + "|" + checkpointPart + "|" + digest;

        PrivateKey priv = keyManager.selfPrivateKey();
        String sig = cryptoUtil.signBase64(payload, priv);
        sig = byzantineService.maybeCorruptSignature(replicaId, sig);

        ViewChange.Builder b = ViewChange.newBuilder()
                .setNewView(targetView)
                .setReplicaId(replicaId)
                .addAllPreparedMessages(preparedEntries)
                .setSignature(sig);

        if (checkpointSummary != null) {
            b.setCheckpoint(checkpointSummary);
        }
        if (certificate != null) {
            b.setCheckpointCertificate(certificate);
        }

        return b.build();
    }

    private NewView buildNewViewMessage(long targetView, Collection<ViewChange> viewChanges) throws Exception {
        String leaderId = nodeState.validPrimaryIdForView(targetView);
        PrivateKey leaderPriv = keyManager.selfPrivateKey();

        CheckpointCertificate chosenCert = selectBestCertificate(viewChanges);
        long checkpointSeq = determineCheckpointSequence(chosenCert, viewChanges);
        List<PrePrepare> included = rebuildPrePreparesForNewView(targetView, leaderId, viewChanges, checkpointSeq);

        CheckpointSummary checkpointSummary = null;
        String cpDigest = "";
        if (chosenCert != null) {
            cpDigest = chosenCert.getDigest();
            checkpointSummary = CheckpointSummary.newBuilder()
                    .setSequence(chosenCert.getSequence())
                    .setDigest(chosenCert.getDigest())
                    .setLabel("CERT")
                    .build();
        } else {
            long bestSeq = 0L;
            String bestDigest = "";
            for (ViewChange vc : viewChanges) {
                if (vc.hasCheckpoint()) {
                    long s = vc.getCheckpoint().getSequence();
                    if (s > bestSeq) {
                        bestSeq = s;
                        bestDigest = vc.getCheckpoint().getDigest();
                    }
                }
            }
            if (bestSeq > 0 && bestDigest != null && !bestDigest.isBlank()) {
                cpDigest = bestDigest;
                checkpointSummary = CheckpointSummary.newBuilder()
                        .setSequence(bestSeq)
                        .setDigest(bestDigest)
                        .setLabel("SUMMARY")
                        .build();
            }
        }

        NewView.Builder b = NewView.newBuilder()
                .setView(targetView)
                .setNewLeaderId(leaderId)
                .addAllViewChanges(viewChanges)
                .addAllIncludedPrePrepares(included);

        if (checkpointSummary != null) b.setCheckpoint(checkpointSummary);
        if (chosenCert != null) b.setCheckpointCertificate(chosenCert);

        String vcDigest = viewChangesDigest(viewChanges);
        String preDigest = prePrepareDigest(included);
        String payload = targetView + "|" + leaderId + "|" + cpDigest + "|" + vcDigest + "|" + preDigest;

        String sig = cryptoUtil.signBase64(payload, leaderPriv);
        sig = byzantineService.maybeCorruptSignature(nodeState.getSelfNodeId(), sig);

        b.setSignature(sig);
        return b.build();
    }

    private CheckpointCertificate selectBestCertificate(Collection<ViewChange> vcs) {
        Map<String, List<CheckpointProof>> grouped = new HashMap<>();
        for (ViewChange vc : vcs) {
            if (vc.hasCheckpointCertificate()) {
                CheckpointCertificate c = vc.getCheckpointCertificate();
                String key = c.getSequence() + "|" + c.getDigest();
                grouped.computeIfAbsent(key, k -> new ArrayList<>()).addAll(c.getProofsList());
            }
        }
        return grouped.entrySet().stream()
                .filter(e -> e.getValue().size() >= nodeState.quorumSize())
                .max(Comparator.comparingLong(e -> Long.parseLong(e.getKey().split("\\|")[0])))
                .map(e -> {
                    String[] parts = e.getKey().split("\\|");
                    return CheckpointCertificate.newBuilder()
                            .setSequence(Long.parseLong(parts[0]))
                            .setDigest(parts[1])
                            .addAllProofs(e.getValue())
                            .build();
                })
                .orElse(null);
    }

    private long determineCheckpointSequence(CheckpointCertificate chosenCert, Collection<ViewChange> vcs) {
        if (chosenCert != null) return chosenCert.getSequence();
        return vcs.stream()
                .mapToLong(vc -> vc.hasCheckpointCertificate() ?
                        vc.getCheckpointCertificate().getSequence() :
                        vc.hasCheckpoint() ? vc.getCheckpoint().getSequence() : 0L)
                .max().orElse(0L);
    }

    private List<PrePrepare> rebuildPrePreparesForNewView(long targetView, String leaderId,
                                                          Collection<ViewChange> vcs, long checkpointSeq) {
        Map<Long, PreparedEntry> preferred = new HashMap<>();
        for (ViewChange vc : vcs) {
            for (PreparedEntry e : vc.getPreparedMessagesList()) {
                if (e.getSequence() <= checkpointSeq) continue;
                preferred.merge(e.getSequence(), e, (a, b) -> b.getView() > a.getView() ? b : a);
            }
        }

        PrivateKey priv = keyManager.selfPrivateKey();
        TreeMap<Long, PrePrepare> rebuilt = new TreeMap<>();

        preferred.values().stream()
                .sorted(Comparator.comparingLong(PreparedEntry::getSequence))
                .forEach(entry -> {
                    long seq = entry.getSequence();
                    nodeState.getPrePrepareLog(seq).ifPresentOrElse(pre -> {
                        try {
                            String toSign = targetView + "|" + seq + "|" + pre.getDigest() + "|" + leaderId;
                            String sig = cryptoUtil.signBase64(toSign, priv);
                            sig = byzantineService.maybeCorruptSignature(nodeState.getSelfNodeId(), sig);
                            rebuilt.put(seq, PrePrepare.newBuilder(pre)
                                    .setView(targetView)
                                    .setLeaderId(leaderId)
                                    .setSignature(ByteString.copyFromUtf8(sig))
                                    .build());
                        } catch (Exception ex) {
                            log.error("[{}] rebuild PrePrepare seq {}: {}", nodeState.getSelfNodeId(), seq, ex.getMessage());
                        }
                    }, () -> {
                        try {
                            var rowOpt = logRepo.findById(seq);
                            if (rowOpt.isPresent() && rowOpt.get().getPrePreparePayload() != null) {
                                var row = rowOpt.get();
                                String json = row.getPrePreparePayload();
                                ClientRequest.Builder rb = ClientRequest.newBuilder();
                                com.google.protobuf.util.JsonFormat.parser().ignoringUnknownFields().merge(json, rb);
                                ClientRequest req = rb.build();

                                String digest = row.getPrePrepareDigest() == null ? entry.getDigest() : row.getPrePrepareDigest();
                                String toSign = targetView + "|" + seq + "|" + digest + "|" + leaderId;
                                String sig = cryptoUtil.signBase64(toSign, priv);
                                sig = byzantineService.maybeCorruptSignature(nodeState.getSelfNodeId(), sig);

                                rebuilt.put(seq, PrePrepare.newBuilder()
                                        .setView(targetView)
                                        .setSequence(seq)
                                        .setDigest(digest)
                                        .setRequest(req)
                                        .setLeaderId(leaderId)
                                        .setSignature(ByteString.copyFromUtf8(sig))
                                        .build());
                                log.warn("[{}] Reconstructed PRE-PREPARE from log for seq={} during NEW-VIEW",
                                        nodeState.getSelfNodeId(), seq);
                            } else {
                                ReplicaLogEntity byDigest = null;
                                if (!entry.getDigest().isBlank()) {
                                    byDigest = logRepo.findTopByDigestOrderByLastUpdatedDesc(entry.getDigest());
                                }
                                if (byDigest != null && byDigest.getPrePreparePayload() != null) {
                                    ClientRequest.Builder rb = ClientRequest.newBuilder();
                                    JsonFormat.parser().ignoringUnknownFields()
                                            .merge(byDigest.getPrePreparePayload(), rb);
                                    ClientRequest req = rb.build();

                                    String digest = cryptoUtil.sha256Base64Bytes(req.toByteArray());
                                    if (!digest.equals(entry.getDigest()) && !entry.getDigest().isBlank()) {
                                        log.warn("[{}] Digest mismatch reconstructing seq {} (prepared={} computed={})",
                                                nodeState.getSelfNodeId(), seq, entry.getDigest(), digest);
                                    }
                                    String toSign = targetView + "|" + seq + "|" + digest + "|" + leaderId;
                                    String sig = cryptoUtil.signBase64(toSign, priv);
                                    sig = byzantineService.maybeCorruptSignature(nodeState.getSelfNodeId(), sig);

                                    rebuilt.put(seq, PrePrepare.newBuilder()
                                            .setView(targetView)
                                            .setSequence(seq)
                                            .setDigest(digest)
                                            .setRequest(req)
                                            .setLeaderId(leaderId)
                                            .setSignature(ByteString.copyFromUtf8(sig))
                                            .build());
                                    log.warn("[{}] Reconstructed PRE-PREPARE from digest match for seq={} during NEW-VIEW",
                                            nodeState.getSelfNodeId(), seq);
                                } else {
                                    Optional<ClientRequest> reconstructed = reconstructFromPreparedEntry(entry);
                                    if (reconstructed.isPresent()) {
                                        ClientRequest req = reconstructed.get();
                                        String digest = cryptoUtil.sha256Base64Bytes(req.toByteArray());
                                        if (!entry.getDigest().isBlank() && !entry.getDigest().equals(digest)) {
                                            log.warn("[{}] Prepared digest {} differs from recomputed {} for seq={}",
                                                    nodeState.getSelfNodeId(), entry.getDigest(), digest, seq);
                                        }
                                        String toSign = targetView + "|" + seq + "|" + digest + "|" + leaderId;
                                        String sig = cryptoUtil.signBase64(toSign, priv);
                                        sig = byzantineService.maybeCorruptSignature(nodeState.getSelfNodeId(), sig);

                                        rebuilt.put(seq, PrePrepare.newBuilder()
                                                .setView(targetView)
                                                .setSequence(seq)
                                                .setDigest(digest)
                                                .setRequest(req)
                                                .setLeaderId(leaderId)
                                                .setSignature(ByteString.copyFromUtf8(sig))
                                                .build());
                                        log.info("[{}] Reconstructed PRE-PREPARE from preparedEntry descriptor for seq={}",
                                                nodeState.getSelfNodeId(), seq);
                                    } else {
                                        ClientRequest noop = ClientRequest.newBuilder()
                                                .setClientId("NOOP")
                                                .setOperation("NOOP")
                                                .build();
                                        String digest = entry.getDigest().isBlank()
                                                ? cryptoUtil.sha256Base64Bytes(noop.toByteArray())
                                                : entry.getDigest();
                                        String toSign = targetView + "|" + seq + "|" + digest + "|" + leaderId;
                                        String sig = cryptoUtil.signBase64(toSign, priv);
                                        sig = byzantineService.maybeCorruptSignature(nodeState.getSelfNodeId(), sig);
                                        rebuilt.put(seq, PrePrepare.newBuilder()
                                                .setView(targetView)
                                                .setSequence(seq)
                                                .setDigest(digest)
                                                .setRequest(noop)
                                                .setLeaderId(leaderId)
                                                .setSignature(ByteString.copyFromUtf8(sig))
                                                .build());
                                        log.warn("[{}] Missing PRE-PREPARE payload for seq={} → inserting NO-OP in NEW-VIEW",
                                                nodeState.getSelfNodeId(), seq);
                                    }
                                }
                            }
                        } catch (Exception ex) {
                            log.error("[{}] Failed to rebuild seq {} from log: {}",
                                    nodeState.getSelfNodeId(), seq, ex.getMessage());
                        }
                    });
                });

        long highestPreparedSeq = preferred.keySet().stream()
                .mapToLong(Long::longValue)
                .max()
                .orElse(checkpointSeq);

        if (highestPreparedSeq > checkpointSeq) {
            for (long seq = checkpointSeq + 1; seq <= highestPreparedSeq; seq++) {
                if (rebuilt.containsKey(seq)) continue;

                ClientRequest noopReq = ClientRequest.newBuilder()
                        .setClientId("NOOP-" + seq)
                        .setOperation("NOOP")
                        .setTimestamp(String.valueOf(seq))
                        .build();

                String digest = cryptoUtil.sha256Base64Bytes(noopReq.toByteArray());
                String toSign = targetView + "|" + seq + "|" + digest + "|" + leaderId;
                String sig = cryptoUtil.signBase64(toSign, priv);
                sig = byzantineService.maybeCorruptSignature(nodeState.getSelfNodeId(), sig);

                rebuilt.put(seq, PrePrepare.newBuilder()
                        .setView(targetView)
                        .setSequence(seq)
                        .setDigest(digest)
                        .setRequest(noopReq)
                        .setLeaderId(leaderId)
                        .setSignature(ByteString.copyFromUtf8(sig))
                        .build());

                log.info("[{}] NEW-VIEW inserting NO-OP at seq={} to fill gap between checkpoint {} and prepared ops",
                        nodeState.getSelfNodeId(), seq, checkpointSeq);
            }
        }

        return new ArrayList<>(rebuilt.values());
    }

    private Optional<ClientRequest> reconstructFromPreparedEntry(PreparedEntry entry) {
        String descriptor = entry.getClientId();
        if (descriptor == null || descriptor.isBlank()) return Optional.empty();

        ClientRequest.Builder builder = ClientRequest.newBuilder();
        try {
            JsonFormat.parser().ignoringUnknownFields().merge(descriptor, builder);
            return Optional.of(builder.build());
        } catch (Exception jsonErr) {
            try {
                TextFormat.getParser().merge(descriptor, builder);
                return Optional.of(builder.build());
            } catch (Exception ignored) {
                ClientRequest.Builder fallback = ClientRequest.newBuilder();
                for (String part : descriptor.split(",")) {
                    String[] kv = part.split("=", 2);
                    if (kv.length != 2) continue;
                    String key = kv[0].trim().toLowerCase(Locale.ROOT);
                    String value = kv[1].trim();
                    switch (key) {
                        case "clientid" -> fallback.setClientId(value);
                        case "operation" -> fallback.setOperation(value);
                        case "fromaccount" -> fallback.setFromAccount(value);
                        case "toaccount" -> fallback.setToAccount(value);
                        case "amount" -> {
                            try { fallback.setAmount(Long.parseLong(value)); } catch (NumberFormatException ignored2) {}
                        }
                        case "timestamp" -> fallback.setTimestamp(value);
                    }
                }
                if (!fallback.getClientId().isEmpty() || !fallback.getOperation().isEmpty()) {
                    return Optional.of(fallback.build());
                }
            }
        }
        return Optional.empty();
    }

    private Acknowledge success(String m) {
        return Acknowledge.newBuilder().setSuccess(true).setMessage(m).build();
    }

    private Acknowledge fail(String m) {
        if (m == null) m = "";
        return Acknowledge.newBuilder().setSuccess(false).setMessage(m).build();
    }

    public void onNewViewInstalled(long view) {
        viewChangePending.set(false);
        pendingViewTarget.set(-1);
        viewChangeStartMs.set(0L);
        viewChangeTimerArmed.set(false);
        resetViewChangeBackoff();
        clearHigherViewEvidence();
        nodeState.clearViewChangeInProgressAtOrBelow(view);
        lastViewInstallMs.set(System.currentTimeMillis());
        executionBaselineSeq.set(nodeState.getLastExecutedSequenceNumber());
    }

    private long effectiveTimeoutMs() {
        int exp = Math.min(viewChangeBackoffExp.get(), MAX_BACKOFF_SHIFT);
        return viewChangeTimeoutMs * (1L << exp);
    }

    private void resetViewChangeBackoff() {
        viewChangeBackoffExp.set(0);
    }

    private void maybeArmViewChangeTimer(long view) {
        if (!viewChangePending.get()) return;
        if (pendingViewTarget.get() != view) return;
        if (viewChangeTimerArmed.get()) return;
        if (nodeState.viewChangesFor(view).size() >= nodeState.quorumSize()) {
            viewChangeStartMs.set(System.currentTimeMillis());
            viewChangeTimerArmed.set(true);
            log.warn("[{}] View-change quorum reached for view {} → timer armed (timeout={} ms)",
                    nodeState.getSelfNodeId(), view, effectiveTimeoutMs());
            refreshHigherViewHint();
        }
    }

    private void maybeFollowHigherViewQuorum() {
        if (!nodeState.isParticipating()) return;
        if (viewChangePending.get()) return;
        if (byzantineService.isCrashed(nodeState.getSelfNodeId())) return;
        long now = System.currentTimeMillis();
        long sinceInstall = now - lastViewInstallMs.get();
        long sinceProgress = now - nodeState.getLastProgressTimestamp();
        long remoteFollowGrace = Math.max(progressTimeoutMs, activityTimeoutMs);
        if (sinceInstall < remoteFollowGrace) {
            return;
        }
        if (sinceProgress < remoteFollowGrace) {
            return;
        }
        long current = nodeState.getCurrentView();
        int threshold = nodeState.getByzantineNodesCount() + 1;
        for (Long candidate : trackedViewNumbers.tailSet(current + 1, true)) {
            int count = nodeState.viewChangesFor(candidate).size();
            if (count >= threshold) {
                if (pendingViewTarget.get() != candidate || !viewChangePending.get()) {
                    log.debug("[{}] Following remote f+1 quorum for view {}", nodeState.getSelfNodeId(), candidate);
                    requestViewChange(candidate, "Remote f+1 view-change quorum", false);
                }
                break;
            }
        }
    }

    private void maybeRecordHigherViewHint(long candidateView) {
        if (!viewChangePending.get()) return;
        if (!viewChangeTimerArmed.get()) return;
        long pending = pendingViewTarget.get();
        if (candidateView <= pending) return;
        int threshold = nodeState.getByzantineNodesCount() + 1;
        if (!hasRemoteQuorum(candidateView, threshold)) return;
        smallestHigherViewHint.accumulateAndGet(candidateView,
                (prev, next) -> prev <= 0 ? next : Math.min(prev, next));
    }

    private void refreshHigherViewHint() {
        if (!viewChangePending.get() || !viewChangeTimerArmed.get()) return;
        long pending = pendingViewTarget.get();
        int threshold = nodeState.getByzantineNodesCount() + 1;
        for (Long candidate : trackedViewNumbers.tailSet(pending + 1, true)) {
            if (hasRemoteQuorum(candidate, threshold)) {
                smallestHigherViewHint.accumulateAndGet(candidate,
                        (prev, next) -> prev <= 0 ? next : Math.min(prev, next));
                break;
            }
        }
    }

    private boolean hasRemoteQuorum(long view, int threshold) {
        if (!trackedViewNumbers.contains(view)) return false;
        Map<String, ViewChange> viewChanges = nodeState.viewChangesFor(view);
        return viewChanges.size() >= threshold;
    }

    private void flushHigherViewEvidenceAfterExecution() {
        long executed = nodeState.getLastExecutedSequenceNumber();
        long baseline = executionBaselineSeq.get();
        if (executed > baseline && !viewChangePending.get()) {
            clearHigherViewEvidence();
            executionBaselineSeq.set(executed);
            log.debug("[{}] Cleared higher-view evidence after execution progress (seq={})",
                    nodeState.getSelfNodeId(), executed);
        }
    }

    private void clearHigherViewEvidence() {
        trackedViewNumbers.clear();
        smallestHigherViewHint.set(-1);
        nodeState.clearViewChangesAtOrAbove(nodeState.getCurrentView() + 1);
    }
}
