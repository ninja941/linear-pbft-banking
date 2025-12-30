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
import com.distributedsystems.pbft.service.ExecutionServiceImpl;
import com.distributedsystems.pbft.service.ThresholdSignatureService;
import com.distributedsystems.pbft.state.NodeState;
import com.distributedsystems.pbft.util.CryptoUtil;
import com.distributedsystems.pbft.util.IValidator;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.JsonFormat;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@Service
@RequiredArgsConstructor
public class CommitPhaseHandlerImpl {

    private final NodeState nodeState;
    private final ReplicaClient replicaClient;
    private final IEncrypterEntity encrypterRepostroy;
    private final CryptoUtil cryptoUtil;
    private final IValidator validator;
    private final ReplicaLogEntry replicaLogEntry;
    private final ByzantineService byzantineService;
    private final ExecutionServiceImpl executionService;
    private final ThresholdSignatureService thresholdSignatureService;

    private final ConcurrentHashMap<Long, AtomicBoolean> commitCollector = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Long, AtomicLong> commitQuorumViews = new ConcurrentHashMap<>();
    private final IDecrypterEntity decrypterRepository;

    @org.springframework.beans.factory.annotation.Value("${pbft.logging.commit.require-preprepare:true}")
    private boolean requirePreForCommitPersist;


    @Transactional
    public Acknowledge onCommitFromBackup(Commit commit) {
        try {
            String selfId = nodeState.getSelfNodeId();
            if (!nodeState.isParticipating()) return fail("Not live");
            if (byzantineService.isCrashed(selfId)) return fail("Crashed");

            long seq = commit.getSequence();
            long view = commit.getView();
            String digest = commit.getDigest();

            DecrypterEntity row = decrypterRepository.findById(commit.getReplicaId())
                    .orElseThrow(() -> new IllegalStateException("Missing pubkey for " + commit.getReplicaId()));
            PublicKey pub = cryptoUtil.publicKeyFromBase64(row.getPublicKey());

            String msg = view + "|" + seq + "|" + digest + "|" + commit.getReplicaId();
            String sigB64 = commit.getSignature().toStringUtf8();

            if (!cryptoUtil.verifyBase64(msg, sigB64, pub)) {
                log.error("[{}]  Invalid signature from {} for COMMIT(seq={}, digest={})",
                        selfId, commit.getReplicaId(), seq, digest);
                return fail("Invalid Commit signature");
            }


            if (!validator.validateCommit(commit))
                return fail("Invalid commit");

            nodeState.commitsFor(seq).add(commit);
            if (thresholdSignatureService.isEnabled()
                    && commit.getThresholdShare() != null
                    && !commit.getThresholdShare().isEmpty()) {
                thresholdSignatureService.registerShare(
                        ThresholdSignatureService.SharePhase.COMMIT,
                        view, seq, digest, commit.getReplicaId(),
                        commit.getThresholdShare().toByteArray());
            }

            nodeState.markActivity();
            log.info("[{}] COMMIT(seq={}, from={}, digest={})",
                    selfId, seq, commit.getReplicaId(), digest);

            if (isPrimaryForView(view)) {
                addLeaderCommitIfMissing(view, seq, digest);

        if (hasCommitQuorum(seq, digest)) {
            onLocalCommitQuorum(view, seq, digest);
        }
            }

            return success("Commited");
        } catch (Exception e) {
            return fail(e.getMessage());
        }
    }

    @Transactional
    public Acknowledge onCommitCertificate(CommitCertificate cert) {
        try {
            if (!nodeState.isParticipating()) return fail("");
            if (byzantineService.isCrashed(nodeState.getSelfNodeId())) return fail("");

            final long seq = cert.getSequence();
            final String digest = cert.getDigest();

            if (!validator.validateCommitCertificate(cert)) return fail("Invalid CommitCertificate");

            nodeState.getCommitCertificates().put(seq, cert);
            log.info("[{}] Validate CommitCertificate seq={} view={} digest={}",
                    nodeState.getSelfNodeId(), seq, cert.getView(), digest);
            upsertCommitted(seq, cert.getView(), digest);

            executionService.execute(seq);

            return success("CommitCertificate applied");
        } catch (Exception e) {
            return fail(e.getMessage());
        }
    }


    private boolean isPrimaryForView(long view) {
        String expectedPrimary = nodeState.validPrimaryIdForView(view);
        return nodeState.getSelfNodeId().equals(expectedPrimary);
    }

    void addLeaderCommitIfMissing(long view, long seq, String digest) {
        final String leaderId = nodeState.getSelfNodeId();
        var commitsSet = nodeState.commitsFor(seq);
        boolean already = commitsSet.stream().anyMatch(c -> c.getReplicaId().equals(leaderId));
        if (already) return;

        try {
            EncrypterEntity row = encrypterRepostroy.findById(leaderId)
                    .orElseThrow(() -> new IllegalStateException("Missing key for " + leaderId));
            PrivateKey priv = cryptoUtil.privateKeyFromBase64(row.getPrivateKey());
            String msg = view + "|" + seq + "|" + digest + "|" + leaderId;
            String sig = cryptoUtil.signBase64(msg, priv);

            Commit.Builder builder = Commit.newBuilder()
                    .setView(view).setSequence(seq).setDigest(digest)
                    .setReplicaId(leaderId)
                    .setSignature(ByteString.copyFromUtf8(sig));

            thresholdSignatureService.createPartialSignature(
                            ThresholdSignatureService.SharePhase.COMMIT,
                            view, seq, digest, leaderId)
                    .ifPresent(bytes -> builder.setThresholdShare(ByteString.copyFrom(bytes)));

            Commit selfCommit = builder.build();

            commitsSet.add(selfCommit);
        } catch (Exception e) {
        }
    }

    private void upsertCommitted(long seq, long view, String digest) {
        var preOpt = nodeState.getPrePrepareLog(seq);
        if (requirePreForCommitPersist && preOpt.isEmpty()) {
            return;
        }

        String reqJson = preOpt.map(pp -> {
            try { return JsonFormat.printer().print(pp.getRequest()); }
            catch (Exception e) { return "{}"; }
        }).orElse("{}");

        replicaLogEntry.upsert(
                seq,
                (int) view,
                digest,
                ReplicaLogEntity.Phase.COMMITTED,
                true,
                reqJson,
                digest,
                reqJson
        );
    }

    private CommitCertificate buildCommitCertificate(long view, long seq, String digest) {
        try {
            String leaderId = nodeState.getSelfNodeId();
            EncrypterEntity row = encrypterRepostroy.findById(leaderId)
                    .orElseThrow(() -> new IllegalStateException("Missing key for " + leaderId));
            PrivateKey priv = cryptoUtil.privateKeyFromBase64(row.getPrivateKey());
            String leaderSig = cryptoUtil.signBase64(view + "|" + seq + "|" + digest + "|" + leaderId, priv);

            CommitCertificate cert = CommitCertificate.newBuilder()
                    .setView(view).setSequence(seq).setDigest(digest)
                    .setLeaderId(leaderId)
                    .setLeaderSignature(ByteString.copyFromUtf8(leaderSig))
                    .addAllCommits(nodeState.commitsFor(seq))
                    .build();

            return thresholdSignatureService.tryAggregate(
                            ThresholdSignatureService.SharePhase.COMMIT,
                            view, seq, digest)
                    .map(bytes -> cert.toBuilder()
                            .clearCommits()
                            .setThresholdMode(true)
                            .setThresholdSignature(ByteString.copyFrom(bytes))
                            .build())
                    .orElse(cert);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private boolean hasCommitQuorum(long seq, String digest) {
        var commits = nodeState.commitsFor(seq);
        synchronized (commits) {
            long count = commits.stream()
                    .filter(c -> c.getDigest().equals(digest))
                    .map(Commit::getReplicaId)
                    .distinct()
                    .count();
            return count >= nodeState.quorumSize();
        }
    }

    private Acknowledge success(String msg) {
        return Acknowledge.newBuilder().setSuccess(true).setMessage(msg).build();
    }
    private Acknowledge fail(String msg) {
        return Acknowledge.newBuilder().setSuccess(false).setMessage(msg).build();
    }

    public void resetLatches() {
        commitQuorumViews.clear();
        commitCollector.clear();
    }

    @Transactional
    public void onLocalCommitQuorum(long view, long seq, String digest) {
        AtomicLong seenView = commitQuorumViews.computeIfAbsent(seq, key -> new AtomicLong(-1L));
        while (true) {
            long prev = seenView.get();
            if (prev >= view) {
                return;
            }
            if (seenView.compareAndSet(prev, view)) {
                break;
            }
        }

        final String selfId = nodeState.getSelfNodeId();
        addLeaderCommitIfMissing(view, seq, digest);
        CommitCertificate certificate = buildCommitCertificate(view, seq, digest);
        upsertCommitted(seq, view, digest);

        try {
            executionService.execute(seq);
            log.info("[{}] Execution begin for  seq={}", selfId, seq);
            nodeState.markProgress();
        } catch (Exception ex) {
        }

        try {
            replicaClient.broadcastCommitCertificate(certificate, nodeState.livePeersExcludingSelf());
            log.info("[{}] Broadcasted CommitCertificate(seq={}, commits={})",
                    selfId, seq, certificate.getCommitsCount());
        } catch (Exception e) {
        }
    }

}
