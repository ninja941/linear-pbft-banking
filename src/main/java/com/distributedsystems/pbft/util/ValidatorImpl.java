package com.distributedsystems.pbft.util;

import com.distributedsystems.pbft.model.DecrypterEntity;
import com.distributedsystems.pbft.proto.*;
import com.distributedsystems.pbft.repository.IDecrypterEntity;
import com.distributedsystems.pbft.state.NodeState;
import com.distributedsystems.pbft.service.ThresholdSignatureService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.util.HashSet;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class ValidatorImpl implements IValidator {

    private final NodeState nodeState;
    private final IDecrypterEntity decrypterRepository;
    private final CryptoUtil cryptoUtil;
    private final ThresholdSignatureService thresholdSignatureService;


    private PublicKey getPublicKey(String nodeId) throws Exception {
        DecrypterEntity row = decrypterRepository.findById(nodeId)
                .orElseThrow(() -> new IllegalStateException("Missing public key for node " + nodeId));
        return cryptoUtil.publicKeyFromBase64(row.getPublicKey());
    }

    private boolean ValidateSignature(String msg, String sigB64, String nodeId) {
        try {
            PublicKey pub = getPublicKey(nodeId);
            return cryptoUtil.verifyBase64(msg, sigB64, pub);
        } catch (Exception e) {
            log.warn("[CertValidator] Signature verify failed for {}: {}", nodeId, e.getMessage());
            return false;
        }
    }

    @Override
    public boolean validateClientRequest(ClientRequest req) {
        return req != null && req.getOperation() != null && !req.getOperation().isBlank();
    }

    @Override
    public boolean validatePrePrepare(PrePrepare m) {
        try {
            if (m == null) return false;

            String expectedLeader = nodeState.validPrimaryIdForView(m.getView());
            if (!expectedLeader.equals(m.getLeaderId())) {
                log.warn("[CertValidator] Invalid PRE-PREPARE: leader={} expected={}", m.getLeaderId(), expectedLeader);
                return false;
            }

            String computed = cryptoUtil.sha256Base64Bytes(m.getRequest().toByteArray());
            if (!computed.equals(m.getDigest())) {
                log.warn("[CertValidator] Invalid PRE-PREPARE: digest mismatch");
                return false;
            }

            String msg = m.getView() + "|" + m.getSequence() + "|" + m.getDigest() + "|" + m.getLeaderId();
            String sig = m.getSignature().toStringUtf8();

            if (!ValidateSignature(msg, sig, m.getLeaderId())) {
                log.warn("[CertValidator] Invalid PRE-PREPARE: bad signature from {}", m.getLeaderId());
                return false;
            }
            return true;

        } catch (Exception e) {
            log.warn("[CertValidator] validatePrePrepare exception: {}", e.getMessage(), e);
            return false;
        }
    }


    @Override
    public boolean validatePrepare(Prepare p) {
        try {
            if (p == null) return false;

            var preOpt = nodeState.getPrePrepareLog(p.getSequence());
            if (preOpt.isEmpty()) {
                log.warn("[CertValidator] Invalid PREPARE: no PrePrepare for seq {}", p.getSequence());
                return false;
            }

            var pre = preOpt.get();
            if (pre.getView() != p.getView() || !pre.getDigest().equals(p.getDigest())) {
                log.warn("[CertValidator] Invalid PREPARE: view/digest mismatch");
                return false;
            }

            String msg = p.getView() + "|" + p.getSequence() + "|" + p.getDigest() + "|" + p.getReplicaId();
            String sig = p.getSignature().toStringUtf8();

            if (!ValidateSignature(msg, sig, p.getReplicaId())) {
                log.warn("[CertValidator] Invalid PREPARE: bad signature from {}", p.getReplicaId());
                return false;
            }
            return true;

        } catch (Exception e) {
            log.warn("[CertValidator] validatePrepare exception: {}", e.getMessage(), e);
            return false;
        }
    }


    @Override
    public boolean validateCommitCertificate(CommitCertificate cert) {
        try {
            if (cert == null || cert.getCommitsCount() == 0) {
                log.warn("[CertValidator] Empty CommitCertificate");
                return false;
            }

            long view = cert.getView();
            long seq = cert.getSequence();
            String digest = cert.getDigest();

            // Validate each commit signature
            Set<String> signers = new HashSet<>();
            for (Commit c : cert.getCommitsList()) {
                if (c.getView() != view || c.getSequence() != seq || !digest.equals(c.getDigest())) {
                    log.warn("[CertValidator] Invalid commit: inconsistent fields from {}", c.getReplicaId());
                    return false;
                }

                String msg = c.getView() + "|" + c.getSequence() + "|" + c.getDigest() + "|" + c.getReplicaId();
                String sig = c.getSignature().toStringUtf8();

                if (!ValidateSignature(msg, sig, c.getReplicaId())) {
                    log.warn("[CertValidator] Invalid commit: bad signature from {}", c.getReplicaId());
                    return false;
                }

                if (!signers.add(c.getReplicaId())) {
                    log.warn("[CertValidator] Duplicate commit from {}", c.getReplicaId());
                    return false;
                }
            }

            if (cert.getThresholdMode()) {
                if (!thresholdSignatureService.isEnabled()) {
                    log.warn("[CertValidator] Threshold certificate received but bonus_2 disabled");
                    return false;
                }
                if (cert.getThresholdSignature().isEmpty()) {
                    log.warn("[CertValidator] Threshold certificate missing aggregate signature");
                    return false;
                }
                return thresholdSignatureService.verifyAggregatedSignature(
                        ThresholdSignatureService.SharePhase.COMMIT,
                        cert.getView(), cert.getSequence(), cert.getDigest(),
                        cert.getThresholdSignature().toByteArray());
            } else {
                if (cert.getCommitsCount() < nodeState.quorumSize()) {
                    log.warn("[CertValidator] CommitCertificate below quorum ({} < {})",
                            cert.getCommitsCount(), nodeState.quorumSize());
                    return false;
                }
            }

            String leaderMsg = view + "|" + seq + "|" + digest + "|" + cert.getLeaderId();
            String leaderSig = cert.getLeaderSignature().toStringUtf8();

            if (!ValidateSignature(leaderMsg, leaderSig, cert.getLeaderId())) {
                log.warn("[CertValidator] Invalid leader signature from {}", cert.getLeaderId());
                return false;
            }

            return true;

        } catch (Exception e) {
            log.warn("[CertValidator] validateCommitCertificate exception: {}", e.getMessage(), e);
            return false;
        }
    }


    @Override
    public boolean hasPrepareCertificate(long seqNo, String digest) {
        var cert = nodeState.getPrepareCertificates().get(seqNo);
        return cert != null && digest.equals(cert.getDigest());
    }

    @Override
    public boolean digestMatches(byte[] payload, String digestB64) {
        return cryptoUtil.sha256Base64Bytes(payload).equals(digestB64);
    }

    @Override
    public boolean checkViewAndSequence(long view, long seqNo) {
        if (view < 0 || seqNo < 0) return false;
        long low = nodeState.getLowWatermark();
        long high = nodeState.getHighWatermark();
        boolean ok = seqNo >= low && seqNo <= high;
        if (!ok) {
            log.warn("[CertValidator] Sequence {} outside watermarks [{}, {}]", seqNo, low, high);
        }
        return ok;
    }

    @Override
    public boolean hasQuorumForPrepare(long view, long seqNo, String digest) {
        long cnt = nodeState.preparesFor(seqNo).stream()
                .filter(p -> p.getView() == view && digest.equals(p.getDigest()))
                .map(Prepare::getReplicaId)
                .distinct()
                .count();
        // PREPARE quorum counts only backups (2f)
        return cnt >= nodeState.getBackupAckCount();
    }

    @Override
    public CommitCertificate appendSignature(CommitCertificate cert, Commit myCommit) {
        boolean exists = cert.getCommitsList().stream()
                .anyMatch(c -> c.getReplicaId().equals(myCommit.getReplicaId()));
        if (exists) return cert;
        return cert.toBuilder().addCommits(myCommit).build();
    }


    @Override
    public boolean validatePrepareCertificate(PrepareCertificate cert) {
        try {
            // Check structural integrity
            if (cert.getDigest().isEmpty() || cert.getLeaderId().isEmpty()) return false;

            // Verify leader signature
            var pubRow = decrypterRepository.findById(cert.getLeaderId())
                    .orElseThrow(() -> new IllegalStateException("Unknown leader " + cert.getLeaderId()));
            PublicKey pub = cryptoUtil.publicKeyFromBase64(pubRow.getPublicKey());

            String msg = cert.getView() + "|" + cert.getSequence() + "|" + cert.getDigest() + "|" + cert.getLeaderId();
            if (!cryptoUtil.verifyBase64(msg, cert.getLeaderSignature().toStringUtf8(), pub))
                return false;

            // Optionally check that prepares included have distinct replica IDs
            if (cert.getThresholdMode()) {
                if (!thresholdSignatureService.isEnabled()) return false;
                if (cert.getThresholdSignature().isEmpty()) return false;
                return thresholdSignatureService.verifyAggregatedSignature(
                        ThresholdSignatureService.SharePhase.PREPARE,
                        cert.getView(), cert.getSequence(), cert.getDigest(),
                        cert.getThresholdSignature().toByteArray());
            } else {
                if (cert.getPreparesCount() == 0) return false;
                long distinctReplicas = cert.getPreparesList().stream()
                        .map(Prepare::getReplicaId)
                        .distinct()
                        .count();

                // Certificate must contain 2f distinct backup prepares
                return distinctReplicas >= nodeState.getBackupAckCount();
            }

        } catch (Exception e) {
            log.error("validatePrepareCertificate error: {}", e.getMessage(), e);
            return false;
        }
    }

    @Override
    public boolean validateCommit(Commit c) {
        try {
            if (c == null) return false;

            var preOpt = nodeState.getPrePrepareLog(c.getSequence());
            if (preOpt.isEmpty()) {
                log.warn("[CertValidator] Invalid COMMIT: no PrePrepare for seq {}", c.getSequence());
                return false;
            }

            var pre = preOpt.get();
            if (pre.getView() != c.getView() || !pre.getDigest().equals(c.getDigest())) {
                log.warn("[CertValidator] Invalid COMMIT: view/digest mismatch");
                return false;
            }

            String msg = c.getView() + "|" + c.getSequence() + "|" + c.getDigest() + "|" + c.getReplicaId();
            String sig = c.getSignature().toStringUtf8();

            if (!ValidateSignature(msg, sig, c.getReplicaId())) {
                log.warn("[CertValidator] Invalid COMMIT: bad signature from {}", c.getReplicaId());
                return false;
            }

            return true;
        } catch (Exception e) {
            log.warn("[CertValidator] validateCommit exception: {}", e.getMessage(), e);
            return false;
        }
    }


}
