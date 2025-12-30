package com.distributedsystems.pbft.service.PhaseHandlers;

import com.distributedsystems.pbft.client.ReplicaClient;
import com.distributedsystems.pbft.model.DecrypterEntity;
import com.distributedsystems.pbft.model.EncrypterEntity;
import com.distributedsystems.pbft.model.ReplicaLogEntity;
import com.distributedsystems.pbft.persistence.ReplicaLogEntry;
import com.distributedsystems.pbft.proto.*;
import com.distributedsystems.pbft.repository.IDecrypterEntity;
import com.distributedsystems.pbft.repository.IEncrypterEntity;
import com.distributedsystems.pbft.service.ByzantineService;
import com.distributedsystems.pbft.service.ThresholdSignatureService;
import com.distributedsystems.pbft.state.NodeState;
import com.distributedsystems.pbft.util.ByzantineInterceptor;
import com.distributedsystems.pbft.util.CryptoUtil;
import com.distributedsystems.pbft.util.IValidator;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.JsonFormat;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;
@Slf4j
@Service
@RequiredArgsConstructor
public class PreparePhaseHandlerImpl {

    private final NodeState nodeState;
    private final ReplicaClient replicaClient;
    private final IEncrypterEntity encrypterRepository;
    private final CryptoUtil cryptoUtil;
    private final IValidator validator;
    private final ReplicaLogEntry replicaLogEntry;
    private final ByzantineService byzantineService;
    private final CommitPhaseHandlerImpl commitHandler;
    private final ThresholdSignatureService thresholdSignatureService;

    @Autowired private ByzantineInterceptor interceptor;
    private final IDecrypterEntity decrypterRepository;
    @Value("${pbft.optimizations.bonus_1.enabled:false}")
    private boolean bonus1Enabled;

    public Acknowledge sendPrepareToLeader(PrePrepare request) {
        try {
            if (!nodeState.isParticipating()) return fail("Not live");
            final String selfId = nodeState.getSelfNodeId();
            if (byzantineService.isCrashed(selfId)) return suppressedByCrash();

            long seq = request.getSequence();
            long view = request.getView();

            EncrypterEntity keyRow = encrypterRepository.findById(selfId)
                    .orElseThrow(() -> new IllegalStateException("No key for " + selfId));
            PrivateKey privKey = cryptoUtil.privateKeyFromBase64(keyRow.getPrivateKey());

            String msg = view + "|" + seq + "|" + request.getDigest() + "|" + selfId;
            String sigB64 = cryptoUtil.signBase64(msg, privKey);
            sigB64 = byzantineService.maybeCorruptSignature(selfId, sigB64);

            Prepare.Builder prepareBuilder = Prepare.newBuilder()
                    .setView(view)
                    .setSequence(seq)
                    .setDigest(request.getDigest())
                    .setReplicaId(selfId)
                    .setSignature(ByteString.copyFromUtf8(sigB64));

            thresholdSignatureService.createPartialSignature(
                            ThresholdSignatureService.SharePhase.PREPARE,
                            view, seq, request.getDigest(), selfId)
                    .ifPresent(bytes -> prepareBuilder.setThresholdShare(ByteString.copyFrom(bytes)));

            Prepare prepare = prepareBuilder.build();

            var leaderMeta = nodeState.nodeInfo(nodeState.validPrimaryIdForView(view))
                    .orElseThrow(() -> new IllegalStateException("Leader not found"));

            if (interceptor.shouldBlock("prepare", leaderMeta.getId())) {
                log.warn("[{}] ByzantineInterceptor blocked prepare send", selfId);
                return fail("");
            }

            replicaClient.sendPrepareToLeader(prepare, leaderMeta);
            log.info("[{}] Sent PREPARE(seq={}, view={}, digest={}) → {}",
                    selfId, seq, view, request.getDigest(), leaderMeta.getId());
            return success("Prepare sent");
        } catch (Exception e) {
            log.error("[{}] sendPrepareToLeader failed: {}", nodeState.getSelfNodeId(), e.getMessage(), e);
            return fail(e.getMessage());
        }
    }

    public Acknowledge onPrepareFromBackup(Prepare prepareReq) {
        try {
            String selfId = nodeState.getSelfNodeId();
            if (!nodeState.isParticipating()) return fail("Not live");

            long seq = prepareReq.getSequence();
            long view = prepareReq.getView();
            String digest = prepareReq.getDigest();

            Optional<PrePrepare> preOpt = nodeState.getPrePrepareLog(seq);
            if (preOpt.isEmpty()) return fail("No PrePrepare");
            PrePrepare pre = preOpt.get();
            if (pre.getView() != view || !pre.getDigest().equals(digest))
                return fail("Digest/view mismatch");

            DecrypterEntity row = decrypterRepository.findById(prepareReq.getReplicaId())
                    .orElseThrow(() -> new IllegalStateException("Missing pubkey for " + prepareReq.getReplicaId()));
            PublicKey pub = cryptoUtil.publicKeyFromBase64(row.getPublicKey());

            String msg = view + "|" + seq + "|" + digest + "|" + prepareReq.getReplicaId();
            String sigB64 = prepareReq.getSignature().toStringUtf8();

            if (!cryptoUtil.verifyBase64(msg, sigB64, pub)) {
                log.error("[{}] Invalid signature from {} for PREPARE(seq={}, digest={})",
                        selfId, prepareReq.getReplicaId(), seq, digest);
                return fail("Bad signature");
            }

            if (!validator.validatePrepare(prepareReq))
                return fail("Invalid prepare");

            nodeState.preparesFor(seq).add(prepareReq);
            nodeState.markActivity();

            log.info("[{}] PREPARE collected (seq={}, total={})", selfId, seq, nodeState.preparesFor(seq).size());
            return success("OK");
        } catch (Exception e) {
            return fail(e.getMessage());
        }
    }


    public Acknowledge onPrepareCertificate(PrepareCertificate cert) {
        try {
            if (!nodeState.isParticipating()) return fail("");
            String selfId = nodeState.getSelfNodeId();
            if (byzantineService.isCrashed(selfId)) return fail("");


            if (!validator.validatePrepareCertificate(cert)) {
                log.error("[{}] PrepareCertificate validation failed for seq={}, view={}, digest={}",
                        nodeState.getSelfNodeId(), cert.getSequence(), cert.getView(), cert.getDigest());
                return fail("Invalid PrepareCertificate");
            }

            long seq = cert.getSequence();
            long view = cert.getView();
            String digest = cert.getDigest();

            PrePrepare pre = nodeState.getPrePrepareLog(seq)
                    .orElseThrow(() -> new IllegalStateException("No PrePrepare for seq=" + seq));
            if (pre.getView() != view || !pre.getDigest().equals(digest))
                return fail("PrepareCertificate mismatch");

            nodeState.getPrepareCertificates().put(seq, cert);
            log.info("[{}] Validate PrepareCertificate seq={} view={} digest={}",
                    selfId, seq, view, digest);
            String reqJson = toJsonSafe(pre.getRequest());
            replicaLogEntry.upsert(seq, (int) view, digest,
                    ReplicaLogEntity.Phase.PREPARED, true,
                    reqJson, pre.getDigest(), reqJson);

            boolean primaryForView = nodeState.amPrimaryForView(view);
            boolean fastPathCert = isBonusFastPathCertificate(cert);

            if (!primaryForView && !fastPathCert) {
                EncrypterEntity me = encrypterRepository.findById(selfId)
                        .orElseThrow(() -> new IllegalStateException("Missing key for " + selfId));
                PrivateKey priv = cryptoUtil.privateKeyFromBase64(me.getPrivateKey());

                String msg = view + "|" + seq + "|" + digest + "|" + selfId;
                String sigB64 = cryptoUtil.signBase64(msg, priv);
                sigB64 = byzantineService.maybeCorruptSignature(selfId, sigB64);

                Commit commit = Commit.newBuilder()
                        .setView(view).setSequence(seq).setDigest(digest)
                        .setReplicaId(selfId)
                        .setSignature(ByteString.copyFromUtf8(sigB64))
                        .build();

                var leaderMeta = nodeState.nodeInfo(nodeState.validPrimaryIdForView(view))
                        .orElseThrow(() -> new IllegalStateException("Primary not found for view=" + view));

                if (!interceptor.shouldBlock("commit", leaderMeta.getId())) {
                    replicaClient.sendCommitToLeader(commit, leaderMeta);
                } else {
                    log.warn("[{}] Commit send blocked by ByzantineInterceptor", selfId);
                }
                return success("PrepareCertificate acknowledged");
            }

            if (!primaryForView) {
                log.info("[{}] Phase optimization: skipping COMMIT send for seq={} (prepares={})",
                        selfId, seq, cert.getPreparesCount());
            }

            String sourceTag = primaryForView ? "leader" : "bonus_1 fast-path";
            applyCertificateCommits(cert, view, seq, digest, sourceTag);

            return success("");
        } catch (Exception e) {
            return fail(e.getMessage());
        }
    }

    private void applyCertificateCommits(PrepareCertificate cert, long view, long seq, String digest, String sourceTag) {
        nodeState.commitsFor(seq).addAll(cert.getPreparesList().stream().map(p ->
                Commit.newBuilder()
                        .setView(view).setSequence(seq).setDigest(digest)
                        .setReplicaId(p.getReplicaId())
                        .setSignature(p.getSignature())
                        .build()).toList());

        commitHandler.addLeaderCommitIfMissing(view, seq, digest);

        long commitCount = nodeState.commitsFor(seq).stream()
                .filter(c -> c.getDigest().equals(digest))
                .map(Commit::getReplicaId)
                .distinct()
                .count();

        log.warn("[{}] {} COMMIT count = {}",
                nodeState.getSelfNodeId(), sourceTag, commitCount, nodeState.quorumSize());

        if (commitCount >= nodeState.quorumSize()) {
            log.info("[{}] {} → COMMIT quorum reached for seq={}", nodeState.getSelfNodeId(), sourceTag, seq);
            commitHandler.onLocalCommitQuorum(view, seq, digest);
        }
    }

    private boolean isBonusFastPathCertificate(PrepareCertificate cert) {
        if (!bonus1Enabled) return false;
        int totalReplicas = nodeState.totalNodes();
        if (totalReplicas <= 0) return false;
        return (cert.getPreparesCount() + 1) >= totalReplicas;
    }

    public boolean hasPrepareQuorum(long seq, String digest) {
        var prepares = nodeState.preparesFor(seq);
        synchronized (prepares) {
            long count = prepares.stream()
                    .filter(p -> p.getDigest().equals(digest))
                    .map(Prepare::getReplicaId)
                    .distinct()
                    .count();
            return count >= nodeState.getBackupAckCount();
        }
    }

    private String toJsonSafe(ClientRequest req) {
        try { return JsonFormat.printer().includingDefaultValueFields().print(req); }
        catch (Exception e) { return req.toString(); }
    }

    private Acknowledge suppressedByCrash() {
        return Acknowledge.newBuilder().setSuccess(false).setMessage("").build();
    }
    private Acknowledge success(String msg) {
        return Acknowledge.newBuilder().setSuccess(true).setMessage(msg).build();
    }
    private Acknowledge fail(String msg) {
        return Acknowledge.newBuilder().setSuccess(false).setMessage(msg).build();
    }
}
