package com.distributedsystems.pbft.service.PhaseHandlers;

import com.distributedsystems.pbft.client.ReplicaClient;
import com.distributedsystems.pbft.model.DecrypterEntity;
import com.distributedsystems.pbft.model.EncrypterEntity;
import com.distributedsystems.pbft.model.ReplicaLogEntity;
import com.distributedsystems.pbft.persistence.ReplicaLogEntry;
import com.distributedsystems.pbft.proto.ClientRequest;
import com.distributedsystems.pbft.proto.PrePrepare;
import com.distributedsystems.pbft.repository.IDecrypterEntity;
import com.distributedsystems.pbft.repository.IEncrypterEntity;
import com.distributedsystems.pbft.service.ByzantineService;
import com.distributedsystems.pbft.state.NodeState;
import com.distributedsystems.pbft.service.ClientRequestAuthenticator;
import com.distributedsystems.pbft.service.ExecutionServiceImpl;
import com.distributedsystems.pbft.util.ByzantineInterceptor;
import com.distributedsystems.pbft.util.CryptoUtil;
import com.distributedsystems.pbft.util.IValidator;
import com.google.protobuf.ByteString;
import com.google.protobuf.Message;
import com.google.protobuf.util.JsonFormat;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Slf4j
@Service
@RequiredArgsConstructor
public class PrePreparePhaseHandlerImpl {

    private final NodeState nodeState;
    private final ReplicaClient replicaClient;
    private final IEncrypterEntity encryterRepository; // existing var name retained
    private final IDecrypterEntity decrypterRepository;
    private final IValidator validator;
    private final ReplicaLogEntry replicaLogEntry;
    private final PreparePhaseHandlerImpl preparePhaseHandler;
    private final ByzantineService byzantineService;
    private final ExecutionServiceImpl executionService;
    private final ClientRequestAuthenticator clientRequestAuthenticator;

    @Autowired private ByzantineInterceptor interceptor;

    /* ----------------------------------------------------------------------
     * Deduplication caches (process-local, cleared by your adminFlush hook)
     * - leaderDigestToSeq:  digest -> sequence the leader already assigned
     * - acceptedDigestToSeq: digest -> sequence a backup already accepted
     * -------------------------------------------------------------------- */
    private final ConcurrentMap<String, Long> leaderDigestToSeq   = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Long> acceptedDigestToSeq = new ConcurrentHashMap<>();

    /**
     * Clear local de-duplication caches. Call this on view-change so replicas
     * can accept the same digest at a different sequence in the new view.
     */
    public void resetDedupCaches() {
        leaderDigestToSeq.clear();
        acceptedDigestToSeq.clear();
        log.debug("[{}] PrePrepare dedup caches cleared (view change)", nodeState.getSelfNodeId());
    }

    /** Leader path: build + broadcast PRE-PREPARE; start timers only after first broadcast. */
    public PrePrepare handleClientRequestAsLeader(ClientRequest request) throws Exception {
        if (!nodeState.isParticipating()) {
            log.warn("[{}] Not in live set → skip PRE-PREPARE", nodeState.getSelfNodeId());
            return null;
        }
        final String selfId = nodeState.getSelfNodeId();

        final long view = nodeState.getCurrentView();
        final String digest = CryptoUtil.sha256Base64Bytes(request.toByteArray());

        // 🚫 Leader de-dup: reuse the SAME sequence for the same digest
        Long existingSeq = leaderDigestToSeq.get(digest);
        final long sequence = (existingSeq != null) ? existingSeq : nodeState.nextSequence();

        // If reusing, we won't re-persist; otherwise we will upsert.
        final boolean isFirstForDigest = (existingSeq == null);
        if (isFirstForDigest) {
            leaderDigestToSeq.putIfAbsent(digest, sequence);
        }

        EncrypterEntity keyRow = encryterRepository.findById(selfId)
                .orElseThrow(() -> new IllegalStateException("Missing key material for leader " + selfId));
        PrivateKey privateKey = CryptoUtil.privateKeyFromBase64(keyRow.getPrivateKey());

        final String toSign = view + "|" + sequence + "|" + digest + "|" + selfId;
        String signatureB64 = CryptoUtil.signBase64(toSign, privateKey);
        signatureB64 = byzantineService.maybeCorruptSignature(selfId, signatureB64);

        PrePrepare pre = PrePrepare.newBuilder()
                .setView(view)
                .setSequence(sequence)
                .setDigest(digest)
                .setRequest(request)
                .setLeaderId(selfId)
                .setSignature(ByteString.copyFromUtf8(signatureB64))
                .build();

        // Cache in-memory (idempotent)
        nodeState.putPrePrepare(pre);

        // Durable log only once per (sequence,digest) pair
        if (isFirstForDigest) {
            final String reqJson = toJsonSafe(request);
            replicaLogEntry.upsert(
                    sequence,
                    (int) view,
                    digest,
                    ReplicaLogEntity.Phase.PRE_PREPARE,
                    true,
                    reqJson,
                    digest,  // prePrepareDigest
                    reqJson  // prePreparePayload
            );
            log.info("[{}] PRE-PREPARE(seq={}, view={}, digest={}) persisted & will be broadcast",
                    selfId, sequence, view, digest);
        } else {
            log.warn("[{}] Reusing PRE-PREPARE for digest={} at existing seq={} (rebroadcast only)",
                    selfId, safePrefix(digest, 8), sequence);
        }

        if (interceptor != null && interceptor.shouldBlock("preprepare")) {
            if (!nodeState.hasStarted()) {
                nodeState.markStarted();
                log.info("[{}] Leader started PBFT timers after first PRE-PREPARE (blocked) seq={} view={}",
                        selfId, sequence, view);
            }
            return pre;
        }

        replicaClient.broadcastPrePrepare(pre, nodeState.livePeersExcludingSelf());

        // ✅ Start timers on the leader only after its first real PRE-PREPARE is sent
        if (!nodeState.hasStarted()) {
            nodeState.markStarted();
            log.info("[{}] Leader started PBFT timers after PRE-PREPARE(seq={}, view={})",
                    selfId, sequence, view);
        }

        return pre;
    }

    /** Backup path: validate, persist once per digest, start timers on first accept, then PREPARE→leader. */
    public boolean validatePrePrepareOnBackup(PrePrepare request) {
        if (!nodeState.isParticipating()) {
            log.warn("[{}] Not in live set → skip validatePrePrepareOnBackup", nodeState.getSelfNodeId());
            return false;
        }
        final String selfId = nodeState.getSelfNodeId();
        final boolean malicious = byzantineService.isCrashed(selfId);

        try {
            log.info("[{}] <<< PRE-PREPARE(seq={}, view={}, digest={}, from={})",
                    selfId,
                    request.getSequence(), request.getView(),
                    safePrefix(request.getDigest(), 8),
                    request.getLeaderId());
            nodeState.markTrafficObserved();
            if (!nodeState.hasStarted()) {
                nodeState.markStarted();
            }

            // 1) Verify leader signature using stored public key
            DecrypterEntity row = decrypterRepository.findById(request.getLeaderId())
                    .orElseThrow(() -> new IllegalStateException("Missing pubkey for " + request.getLeaderId()));
            PublicKey pub = CryptoUtil.publicKeyFromBase64(row.getPublicKey());

            String signedMsg = request.getView() + "|" + request.getSequence() + "|" +
                    request.getDigest() + "|" + request.getLeaderId();
            String sigB64 = request.getSignature().toStringUtf8();

            if (!CryptoUtil.verifyBase64(signedMsg, sigB64, pub)) {
                log.error("[{}] Invalid PRE-PREPARE signature from {} for seq={}",
                        selfId, request.getLeaderId(), request.getSequence());
                return false;
            }

            // 2) Structural / payload validator
            if (!validator.validatePrePrepare(request)) {
                log.warn("[{}] PRE-PREPARE REJECTED (seq={}, failed validator)", selfId, request.getSequence());
                return false;
            }

            try {
                clientRequestAuthenticator.verify(request.getRequest());
            } catch (Exception verifyErr) {
                log.warn("[{}] PRE-PREPARE(seq={}, view={}) rejected due to client signature: {}",
                        selfId, request.getSequence(), request.getView(), verifyErr.getMessage());
                return false;
            }

            // 2b) Ensure the message really comes from the expected primary for that view.
            String expectedLeader = nodeState.validPrimaryIdForView(request.getView());
            if (!Objects.equals(expectedLeader, request.getLeaderId())) {
                log.warn("[{}] Ignoring PRE-PREPARE(seq={}, view={}) from {} (expected leader {})",
                        selfId, request.getSequence(), request.getView(), request.getLeaderId(), expectedLeader);
                return false;
            }

            // 3) Conflict checks
            //    a) If we already accepted this digest at *any* sequence, reject duplicates.
            Long prevSeqForDigest = acceptedDigestToSeq.get(request.getDigest());
            if (prevSeqForDigest != null && !Objects.equals(prevSeqForDigest, request.getSequence())) {
                // Allow digest reuse across different sequences only for explicit NO-OP payloads
                boolean isNoop = "NOOP".equalsIgnoreCase(request.getRequest().getOperation());
                if (!isNoop) {
                    log.warn("[{}] Duplicate PRE-PREPARE for digest={} at new seq={} (already had seq={}) → IGNORE",
                            selfId, safePrefix(request.getDigest(), 8), request.getSequence(), prevSeqForDigest);
                    return false;
                } else {
                    log.info("[{}] Allowing NO-OP digest reuse across sequences (had seq={}, now seq={})",
                            selfId, prevSeqForDigest, request.getSequence());
                }
            }

            //    b) Conflict at same seq with different digest: allow replacement if incoming view is higher.
            PrePrepare existingAtSeq = nodeState.getPrePrepareLogMap().get(request.getSequence());
            if (existingAtSeq != null && !existingAtSeq.getDigest().equals(request.getDigest())) {
                if (request.getView() > existingAtSeq.getView()) {
                    log.warn("[{}] PRE-PREPARE conflict at seq={} but higher view ({}>{}) → REPLACE",
                            selfId, request.getSequence(), request.getView(), existingAtSeq.getView());
                    // Replace in-memory entry with higher-view pre-prepare
                    nodeState.putPrePrepare(request);
                    // Clear any old digest→seq mapping for the sequence we are replacing
                    Long mappedSeq = acceptedDigestToSeq.get(existingAtSeq.getDigest());
                    if (mappedSeq != null && mappedSeq.equals(request.getSequence())) {
                        acceptedDigestToSeq.remove(existingAtSeq.getDigest());
                    }
                } else {
                    log.warn("[{}] PRE-PREPARE conflict at seq={} ({} != {}) in same/older view → REJECT",
                            selfId, request.getSequence(), existingAtSeq.getDigest(), request.getDigest());
                    return false;
                }
            }

            // 4) Persist once per digest (idempotent when re-seen with same seq)
            // Already put above if we replaced; ensure present otherwise
            if (nodeState.getPrePrepareLogMap().get(request.getSequence()) == null
                    || !Objects.equals(nodeState.getPrePrepareLogMap().get(request.getSequence()).getDigest(), request.getDigest())
                    || nodeState.getPrePrepareLogMap().get(request.getSequence()).getView() != request.getView()) {
                nodeState.putPrePrepare(request);
            }
            nodeState.markProgress(); // any accepted PRE-PREPARE counts as forward progress
            if (prevSeqForDigest == null) {
                final String reqJson = toJsonSafe(request.getRequest());
                replicaLogEntry.upsert(
                        request.getSequence(),
                        (int) request.getView(),
                        request.getDigest(),
                        ReplicaLogEntity.Phase.PRE_PREPARE,
                        true,
                        reqJson,
                        request.getDigest(),  // prePrepareDigest
                        reqJson               // prePreparePayload
                );
                acceptedDigestToSeq.putIfAbsent(request.getDigest(), request.getSequence());
                log.info("[{}] Accepted PRE-PREPARE(seq={}, view={}, digest={})",
                        selfId, request.getSequence(), request.getView(), request.getDigest());
            } else {
                log.info("[{}] PRE-PREPARE (digest duplicate) seen again at same seq={}, ignored re-persist.",
                        selfId, request.getSequence());
            }

            // ✅ Start timers on backups after they accept their first PRE-PREPARE
            if (!nodeState.hasStarted()) {
                nodeState.markStarted();
                log.info("[{}] Backup started PBFT timers after first PRE-PREPARE(seq={}, view={})",
                        selfId, request.getSequence(), request.getView());
            }

            // 5) Non-leader backups respond with PREPARE → leader (unless malicious/crash)
            if (!selfId.equals(request.getLeaderId()) && !malicious) {
                preparePhaseHandler.sendPrepareToLeader(request);
            } else if (malicious) {
                log.warn("[{}] Malicious backup (crash attack) suppressing PREPARE for seq={}",
                        selfId, request.getSequence());
            }

            // If COMMIT may have been observed earlier and execution was deferred
            // due to missing PRE-PREPARE, drain now that we have it.
            try {
                executionService.drainDeferred();
            } catch (Exception ignored) { }

            return true;
        } catch (Exception e) {
            log.error("[{}] PRE-PREPARE validation error: {}", selfId, e.getMessage(), e);
            return false;
        }
    }

    /* ------------------------ helpers ------------------------ */

    private static String safePrefix(String s, int n) {
        return (s == null) ? "null" : s.substring(0, Math.min(n, s.length()));
    }

    private String toJsonSafe(Message m) {
        try {
            return JsonFormat.printer().includingDefaultValueFields().print(m);
        } catch (Exception e) {
            return m.toString();
        }
    }
}
