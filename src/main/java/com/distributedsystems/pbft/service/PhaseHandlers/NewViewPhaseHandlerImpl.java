package com.distributedsystems.pbft.service.PhaseHandlers;

import com.distributedsystems.pbft.client.ReplicaClient;
import com.distributedsystems.pbft.persistence.KeyManager;
import com.distributedsystems.pbft.persistence.ReplicaLogEntry;
import com.distributedsystems.pbft.proto.*;
import com.distributedsystems.pbft.service.PbftTimerService;
import com.distributedsystems.pbft.state.NodeState;
import com.distributedsystems.pbft.util.ByzantineInterceptor;
import com.distributedsystems.pbft.util.CryptoUtil;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.util.*;

import static com.distributedsystems.pbft.util.ViewChangeCodec.checkpointDigest;
import static com.distributedsystems.pbft.util.ViewChangeCodec.prePrepareDigest;
import static com.distributedsystems.pbft.util.ViewChangeCodec.viewChangesDigest;

@RequiredArgsConstructor
@Service
@Slf4j
public class NewViewPhaseHandlerImpl {

    private final NodeState nodeState;
    private final ReplicaClient replicaClient;
    private final PrePreparePhaseHandlerImpl prePreparePhaseHandler;
    private final CryptoUtil cryptoUtil;
    private final KeyManager keyManager;
    private final @Lazy PbftTimerService timerService;
    private final ReplicaLogEntry replicaLogEntry;

    private final ByzantineInterceptor interceptor;

    public Acknowledge onNewView(NewView req) {
        boolean spectator = !nodeState.isParticipating();
        try {
            if (nodeState.getCurrentView() >= req.getView()) {
                return success("");
            }

            if (!verifyNewView(req)) {
                return fail("Invalid NEW-VIEW");
            }

            installNewView(req, spectator);
            return success("NewView ADOPTED");
        } catch (Exception e) {
            return fail(e.getMessage());
        }
    }


    private boolean verifyNewView(NewView req) throws Exception {
        String expectedLeader = nodeState.validPrimaryIdForView(req.getView());
        if (!expectedLeader.equals(req.getNewLeaderId())) return false;
        if (req.getViewChangesCount() < nodeState.quorumSize()) return false;

        PublicKey key = keyManager.publicKeyOf(expectedLeader);

        String cpDigest = "";
        if (req.hasCheckpointCertificate()) {
            cpDigest = req.getCheckpointCertificate().getDigest();
            for (CheckpointProof proof : req.getCheckpointCertificate().getProofsList()) {
                try {
                    PublicKey pk = keyManager.publicKeyOf(proof.getReplicaId());
                    String msg = req.getCheckpointCertificate().getSequence() + "|" + cpDigest;
                    if (!cryptoUtil.verifyBase64(msg, proof.getSignature(), pk)) {
                        return false;
                    }
                } catch (Exception ex) {
                    return false;
                }
            }
        } else if (req.hasCheckpoint()) {
            cpDigest = checkpointDigest(req.getCheckpoint());
        }

        String vcDigest = viewChangesDigest(req.getViewChangesList());
        String preDigest = prePrepareDigest(req.getIncludedPrePreparesList());
        String payload = req.getView() + "|" + expectedLeader + "|" + cpDigest + "|" + vcDigest + "|" + preDigest;

        return cryptoUtil.verifyBase64(payload, req.getSignature(), key);
    }


    private void installNewView(NewView req, boolean spectator) {
        long view = req.getView();
        String newLeader = req.getNewLeaderId();

        log.info("[{}] ADOPTING NEW-VIEW view={} leader={}", nodeState.getSelfNodeId(), view, newLeader);

        nodeState.setCurrentView((int) view);
        nodeState.rememberNewView(req);
        nodeState.clearViewChanges(view);
        nodeState.updateLeader(newLeader);
        nodeState.markProgress();
        nodeState.markActivity();

        if (!spectator && timerService != null) {
            timerService.resetAfterNewView();
        }

        if (!spectator) {
            prePreparePhaseHandler.resetDedupCaches();
        }

        if (spectator) {
            return;
        }

        if (req.hasCheckpointCertificate()) {
            CheckpointCertificate cert = req.getCheckpointCertificate();
            int checkpointSeq = (int) cert.getSequence();

            if (checkpointSeq > nodeState.getLastCheckpointSequenceNumber()) {
                nodeState.markCheckpointSequenceNumber(checkpointSeq);
            }
            nodeState.setLastCheckpointLabel("CERTIFICATE:" + cert.getDigest().substring(0, Math.min(8, cert.getDigest().length())));

            try {
                String serialized = nodeState.loadSerializedStateForCheckpoint(cert.getSequence());
                if (serialized != null && !serialized.isEmpty()) {
                    int lastCommit = nodeState.getLastCommitSequenceNumber();
                    if (lastCommit < checkpointSeq) {
                        restoreStateFromJson(serialized);
                        nodeState.setLastCommitSequenceNumber(checkpointSeq);
                        nodeState.setNextSequence(checkpointSeq + 1L);
                    }
                }
            } catch (Exception ex) {
            }

            log.info("[{}] Created checkpoint certificate seq={} proofs={}", nodeState.getSelfNodeId(),
                    cert.getSequence(), cert.getProofsCount());
        } else if (req.hasCheckpoint()) {
            int checkpointSeq = (int) req.getCheckpoint().getSequence();
            if (checkpointSeq > nodeState.getLastCheckpointSequenceNumber()) {
                nodeState.markCheckpointSequenceNumber(checkpointSeq);
            }
            nodeState.setLastCheckpointLabel(req.getCheckpoint().getLabel());
        }

        for (ViewChange vc : req.getViewChangesList()) {
            nodeState.viewChangesFor(view).put(vc.getReplicaId(), vc);
        }

        List<PrePrepare> prePrepares = new ArrayList<>(req.getIncludedPrePreparesList());

        if (prePrepares.isEmpty()) {
        }

        for (PrePrepare pre : prePrepares) {
            nodeState.putPrePrepare(pre);
            safeUpsertPrePrepare(pre);

            if (!nodeState.getSelfNodeId().equals(newLeader)) {
                prePreparePhaseHandler.validatePrePrepareOnBackup(pre);
            }
        }

        if (nodeState.getSelfNodeId().equals(newLeader)) {
            var peers = nodeState.livePeersExcludingSelf();
            if (!interceptor.shouldBlock("preprepare")) {
                for (PrePrepare pre : prePrepares) {
                    replicaClient.broadcastPrePrepare(pre, peers);
                }
            }
        }

        Optional.ofNullable(nodeState.getViewChangeHandler())
                .ifPresent(handler -> handler.onNewViewInstalled(view));

        long highestIncluded = prePrepares.stream()
                .mapToLong(PrePrepare::getSequence)
                .max()
                .orElse(0L);
        long highestPrepared = req.getViewChangesList().stream()
                .flatMap(vc -> vc.getPreparedMessagesList().stream())
                .mapToLong(PreparedEntry::getSequence)
                .max()
                .orElse(0L);
        long baseline = Math.max(nodeState.getLastCommitSequenceNumber(),
                Math.max(nodeState.getLastExecutedSequenceNumber(), Math.max(highestIncluded, highestPrepared)));
        if (baseline > 0) {
            nodeState.setNextSequence(baseline + 1);
        }
    }

    private void safeUpsertPrePrepare(PrePrepare pre) {
        try {
            final long seq = pre.getSequence();
            final int viewAsInt = (int) pre.getView();      // proto uint64 → Java long → int (your upsert signature)

            String requestJson;
            try {
                requestJson = com.google.protobuf.util.JsonFormat.printer()
                        .omittingInsignificantWhitespace()
                        .print(pre.getRequest());
            } catch (Exception e) {
                requestJson = pre.getRequest().toString();
            }

            replicaLogEntry.upsert(
                    seq,
                    viewAsInt,
                    pre.getDigest(),
                    com.distributedsystems.pbft.model.ReplicaLogEntity.Phase.PRE_PREPARE,
                    false,
                    requestJson,
                    pre.getDigest(),
                    requestJson
            );
        } catch (Exception e) {

        }
    }


    private void restoreStateFromJson(String serialized) {
        try {
            Map<String, Long> snapshot = new ObjectMapper().readValue(serialized, new TypeReference<>() {});
            nodeState.restoreBalances(snapshot);
        } catch (Exception e) {
        }
    }

    private Acknowledge success(String msg) {
        return Acknowledge.newBuilder().setSuccess(true).setMessage(msg).build();
    }

    private Acknowledge fail(String msg) {
        if (msg == null) msg = "";
        return Acknowledge.newBuilder().setSuccess(false).setMessage(msg).build();
    }
}
