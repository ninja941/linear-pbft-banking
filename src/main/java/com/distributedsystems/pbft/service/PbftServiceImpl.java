package com.distributedsystems.pbft.service;

import com.distributedsystems.pbft.proto.*;
import com.distributedsystems.pbft.state.NodeState;
import com.distributedsystems.pbft.service.PhaseHandlers.*;
import com.distributedsystems.pbft.service.ClientRequestAuthenticator;
import com.distributedsystems.pbft.util.CSVHandler.CSVScenarioConcurrentService;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.devh.boot.grpc.server.service.GrpcService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Slf4j
@GrpcService
@RequiredArgsConstructor
@Lazy
public class PbftServiceImpl extends PbftServiceGrpc.PbftServiceImplBase {

    private static final Set<String> SPECTATOR_ALLOWED_PHASES = Set.of("ADMIN TIMER", "ADMIN FLUSH");

    private final NodeState nodeState;
    private final PrePreparePhaseHandlerImpl prePrepareHandler;
    private final PreparePhaseHandlerImpl prepareHandler;
    private final CommitPhaseHandlerImpl commitHandler;
    private final ViewChangePhaseHandlerImpl viewChangeHandler;
    private final NewViewPhaseHandlerImpl newViewHandler;
    private final @Lazy CSVScenarioConcurrentService csvScenarioConcurrentService;
    private final ByzantineService byzantineService;
    private final CheckpointService checkpointService;
    private final PbftTimerService pbftTimerService;
    private final ClientRequestAuthenticator clientRequestAuthenticator;

    @Autowired
    private PrimaryImplementation primary;
    @Autowired
    private com.distributedsystems.pbft.repository.IReplicatLogRepository replicaLogRepository;
    private boolean shouldProcessPhase(StreamObserver<Acknowledge> out, Object request, String phaseName) {
        if (!nodeState.isParticipating()) {
            if (phaseName != null && SPECTATOR_ALLOWED_PHASES.contains(phaseName)) {
                return true;
            }


            out.onNext(Acknowledge.newBuilder()
                    .setSuccess(false)
                    .setMessage("LIVE_SET_IGNORE")
                    .build());
            out.onCompleted();
            return false;
        }
        return true;
    }

    private boolean shouldAcceptFrom(String replicaId) {
        if (replicaId == null || replicaId.isBlank()) return true;
        if (!nodeState.isLive(replicaId)) {
            log.debug("[{}] Ignoring message from dead node {}", nodeState.getSelfNodeId(), replicaId);
            return false;
        }
        return true;
    }

    private static int extractNodeNumSafe(String nodeId) {
        if (nodeId == null || nodeId.isBlank()) return -1;
        String digits = nodeId.replaceAll("[^0-9]", "");
        if (digits.isEmpty()) return -1;
        try {
            return Integer.parseInt(digits);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    @Override
    public void submitClientRequest(ClientRequest req, StreamObserver<ClientReply> out) {
        final String self = nodeState.getSelfNodeId();
        try {
            if (!nodeState.isParticipating()) {
                log.warn("[{}] Not in live set → rejecting client {}", self, req.getClientId());
                ClientReply reply = ClientReply.newBuilder()
                        .setClientId(req.getClientId())
                        .setReplicaId(self)
                        .setResult("LIVE_SET_IGNORE")
                        .setView(nodeState.getCurrentView())
                        .build();
                out.onNext(reply);
                out.onCompleted();
                return;
            }

            try {
                String digest = com.distributedsystems.pbft.util.CryptoUtil.sha256Base64Bytes(req.toByteArray());
                var latest = replicaLogRepository.findTopByDigestOrderByLastUpdatedDesc(digest);
                if (latest != null && latest.getPhase() == com.distributedsystems.pbft.model.ReplicaLogEntity.Phase.EXECUTED) {
                    String res = latest.getExecResult();
                    if (res == null || res.isBlank()) res = "SUCCESS";
                    ClientReply reply = ClientReply.newBuilder()
                            .setClientId(req.getClientId())
                            .setSequence((int) latest.getSequenceNumber())
                            .setReplicaId(self)
                            .setResult(res)
                            .setView(nodeState.getCurrentView())
                            .build();
                    out.onNext(reply);
                    out.onCompleted();
                    return;
                }
            } catch (Exception ignored) {}

            try {
                clientRequestAuthenticator.verify(req);
            } catch (Exception verifyErr) {

                out.onError(Status.PERMISSION_DENIED
                        .withDescription("INVALID_CLIENT_SIGNATURE: " + verifyErr.getMessage())
                        .asRuntimeException());
                return;
            }

            if (!nodeState.isPrimary()) {

                ClientReply forwardReply = forwardRequestToPrimary(req);
                if (forwardReply != null) {
                    boolean ok = Optional.ofNullable(forwardReply.getResult())
                            .map(r -> !r.isBlank()
                                    && !r.toUpperCase(Locale.ROOT).startsWith("FAILED")
                                    && !"LIVE_SET_IGNORE".equalsIgnoreCase(r))
                            .orElse(false);

                    ClientReply reply = forwardReply.toBuilder()
                            .setReplicaId(self)
                            .setView(nodeState.getCurrentView())
                            .build();

                    out.onNext(reply);
                    out.onCompleted();
                    return;
                }

                out.onError(Status.UNAVAILABLE
                        .withDescription("Forward to primary failed (no reply)")
                        .asRuntimeException());
                return;
            }

            PrePrepare pre = null;
            try {
                pre = primary.onClientRequest(req);
            } catch (DataIntegrityViolationException dup) {
                long lastSeq = nodeState.getLastCommitSequenceNumber() > 0
                        ? nodeState.getLastCommitSequenceNumber() + 1
                        : nodeState.getLastExecutedSequenceNumber() + 1;

                pre = nodeState.getPrePrepareLog(lastSeq)
                        .orElseThrow(() -> new IllegalStateException("Existing PRE-PREPARE not found after duplicate insert"));
            }

            ClientReply reply = ClientReply.newBuilder()
                    .setClientId(req.getClientId())
                    .setSequence((int) pre.getSequence())
                    .setReplicaId(self)
                    .setResult("ACCEPTED")
                    .setView(pre.getView())
                    .build();

            out.onNext(reply);
            out.onCompleted();

        } catch (Exception e) {
            out.onError(Status.INTERNAL
                    .withDescription("Client request failed: " + e.getMessage())
                    .withCause(e)
                    .asRuntimeException());
        }
    }


    @Override
    public void adminAttack(AttackConfig request, StreamObserver<Acknowledge> responseObserver) {
        try {
            if (request.getClear() || request.getNodesCount() == 0 || request.getAttackType().isBlank()) {
                byzantineService.clearAttack();
            } else {
                var nodes = new java.util.HashSet<Integer>(request.getNodesList());
                var victims = new LinkedHashSet<Integer>(request.getVictimsList());
                byzantineService.configureAttack(request.getAttackType(), nodes, victims);

                String self = nodeState.getSelfNodeId();
                int selfNum = extractNodeNumSafe(self);
                if (selfNum >= 0 && nodes.contains(selfNum)) {
                    byzantineService.markSelfCrashed(self, request.getAttackType());
                }
            }

            responseObserver.onNext(Acknowledge.newBuilder()
                    .setSuccess(true)
                    .setMessage("ATTACK_APPLIED")
                    .build());
            responseObserver.onCompleted();
        } catch (Exception e) {
            responseObserver.onNext(Acknowledge.newBuilder()
                    .setSuccess(false)
                    .setMessage(e.getMessage())
                    .build());
            responseObserver.onCompleted();
        }
    }

    @Override
    public void adminRoster(RosterConfig request, StreamObserver<Acknowledge> responseObserver) {
        try {
            Set<Integer> live = new LinkedHashSet<>(request.getLiveList());
            if (live.isEmpty()) {
                responseObserver.onNext(Acknowledge.newBuilder()
                        .setSuccess(false)
                        .setMessage("LIVE_SET_EMPTY")
                        .build());
                responseObserver.onCompleted();
                return;
            }

            nodeState.replaceLiveSet(live);

            responseObserver.onNext(Acknowledge.newBuilder()
                    .setSuccess(true)
                    .setMessage("ROSTER_APPLIED")
                    .build());
            responseObserver.onCompleted();
        } catch (Exception e) {
            responseObserver.onNext(Acknowledge.newBuilder()
                    .setSuccess(false)
                    .setMessage(e.getMessage())
                    .build());
            responseObserver.onCompleted();
        }
    }

    public ClientReply forwardRequestToPrimary(ClientRequest clientRequest) {
        String self = nodeState.getSelfNodeId();

        if (!nodeState.isParticipating()) {
            return ClientReply.newBuilder()
                    .setClientId(clientRequest.getClientId())
                    .setReplicaId(self)
                    .setResult("LIVE_SET_IGNORE")
                    .setView(nodeState.getCurrentView())
                    .build();
        }

        try {
            clientRequestAuthenticator.verify(clientRequest);
        } catch (Exception verifyErr) {

            return ClientReply.newBuilder()
                    .setClientId(clientRequest.getClientId())
                    .setReplicaId(self)
                    .setResult("FAILED_INVALID_SIGNATURE")
                    .setView(nodeState.getCurrentView())
                    .build();
        }

        if (nodeState.isPrimary()) {
            try {
                primary.onClientRequest(clientRequest);
                return ClientReply.newBuilder()
                        .setClientId(clientRequest.getClientId())
                        .setResult("SUCCESS")
                        .build();
            } catch (Exception e) {
                return ClientReply.newBuilder()
                        .setClientId(clientRequest.getClientId())
                        .setResult("FAILED")
                        .build();
            }
        }

        String primaryAddr = nodeState.getPrimaryNodeId();
        if (primaryAddr == null || primaryAddr.isBlank()) {
            primaryAddr = "localhost:9091";
            nodeState.setPrimaryNodeId(primaryAddr);
        }

        try {
            String[] parts = primaryAddr.split(":");
            String host = parts[0];
            int port = Integer.parseInt(parts[1]);

            ManagedChannel channel = ManagedChannelBuilder
                    .forAddress(host, port)
                    .usePlaintext()
                    .build();

            PbftServiceGrpc.PbftServiceBlockingStub stub = PbftServiceGrpc.newBlockingStub(channel)
                    .withDeadlineAfter(1500, TimeUnit.MILLISECONDS);

            ClientReply reply = stub.submitClientRequest(clientRequest);

            channel.shutdownNow();
            log.info("[{}] Forwarded client request (clientId={}, ts={}) → primary {} → result={}",
                    self, clientRequest.getClientId(), clientRequest.getTimestamp(), primaryAddr,
                    (reply != null ? reply.getResult() : "null"));

            return reply != null
                    ? reply
                    : ClientReply.newBuilder()
                    .setClientId(clientRequest.getClientId())
                    .setResult("FAILED_NULL_REPLY")
                    .build();

        } catch (StatusRuntimeException e) {
            viewChangeHandler.requestViewChange("RPC failure contacting " + primaryAddr + ": " + e.getStatus());
            return ClientReply.newBuilder()
                    .setClientId(clientRequest.getClientId())
                    .setResult("FAILED_GRPC")
                    .build();

        } catch (Exception ex) {
            viewChangeHandler.requestViewChange("Exception contacting " + primaryAddr + ": " + ex.getMessage());
            return ClientReply.newBuilder()
                    .setClientId(clientRequest.getClientId())
                    .setResult("FAILED_EXCEPTION")
                    .build();
        }
    }

    @Override
    public void prePreparePhase(PrePrepare request, StreamObserver<Acknowledge> responseObserver) {
        if (!shouldProcessPhase(responseObserver, request, "PRE-PREPARE")) return;

        String self = nodeState.getSelfNodeId();
        log.info("[{}] Received PrePrepare(seq={}, digest={})", self, request.getSequence(), request.getDigest());

        boolean ok = prePrepareHandler.validatePrePrepareOnBackup(request);

        Acknowledge ack = Acknowledge.newBuilder()
                .setSuccess(ok)
                .setMessage(ok ? "PrePrepare accepted" : "Rejected: digest mismatch")
                .setView(request.getView())
                .setSequence(request.getSequence())
                .build();

        responseObserver.onNext(ack);
        responseObserver.onCompleted();
    }

    @Override
    public void preparePhase(Prepare request, StreamObserver<Acknowledge> responseObserver) {
        if (!shouldProcessPhase(responseObserver, request, "PREPARE")) return;

        String self = nodeState.getSelfNodeId();
        if (!shouldAcceptFrom(request.getReplicaId())) {
            responseObserver.onNext(Acknowledge.newBuilder()
                    .setSuccess(false)
                    .setMessage("Ignored: sender not in live set for this round").build());
            responseObserver.onCompleted();
            return;
        }

        log.info("[{}] Received PREPARE(seq={}, digest={})", self, request.getSequence(), request.getDigest());
        Acknowledge ack = nodeState.amPrimaryForView(request.getView()) ? primary.onPrepareFromBackup(request) : prepareHandler.onPrepareFromBackup(request);

        boolean quorum = prepareHandler.hasPrepareQuorum(request.getSequence(), request.getDigest());
        if (quorum) {
            log.info("[{}] PREPARE quorum reached locally for seq={}", self, request.getSequence());
        }

        responseObserver.onNext(ack);
        responseObserver.onCompleted();
    }

    @Override
    public void commitPhase(Commit request, StreamObserver<Acknowledge> responseObserver) {
        if (!shouldProcessPhase(responseObserver, request, "COMMIT")) return;

        String self = nodeState.getSelfNodeId();
        if (!shouldAcceptFrom(request.getReplicaId())) {
            responseObserver.onNext(Acknowledge.newBuilder()
                    .setSuccess(false)
                    .setMessage("Ignored: sender not in live set for this round").build());
            responseObserver.onCompleted();
            return;
        }

        log.info("[{}] Received Commit(seq={}, digest={})", self, request.getSequence(), request.getDigest());
        Acknowledge ack = commitHandler.onCommitFromBackup(request);

        responseObserver.onNext(ack);
        responseObserver.onCompleted();
    }

    @Override
    public void viewChangePhase(ViewChange request, StreamObserver<Acknowledge> responseObserver) {
        if (!shouldProcessPhase(responseObserver, request, "VIEW CHANGE")) return;

        String self = nodeState.getSelfNodeId();
        if (!shouldAcceptFrom(request.getReplicaId())) {
            responseObserver.onNext(Acknowledge.newBuilder()
                    .setSuccess(false)
                    .setMessage("Ignored: sender not in live set for this round").build());
            responseObserver.onCompleted();
            return;
        }



        log.warn("[{}] Received ViewChange from node={} newView={}",
                self, request.getReplicaId(), request.getNewView());

        Acknowledge ack = viewChangeHandler.onViewChange(request);
        responseObserver.onNext(ack);
        responseObserver.onCompleted();
    }

    @Override
    public void newViewPhase(NewView request, StreamObserver<Acknowledge> responseObserver) {
        if (!shouldProcessPhase(responseObserver, request, "NEW VIEW CHANGE")) return;

        String self = nodeState.getSelfNodeId();
        if (!shouldAcceptFrom(request.getNewLeaderId())) {
            responseObserver.onNext(Acknowledge.newBuilder()
                    .setSuccess(false)
                    .setMessage("Ignored: sender not in live set for this round").build());
            responseObserver.onCompleted();
            return;
        }

        log.warn("[{}] Received NewView(view={}, newLeader={})",
                self, request.getView(), request.getNewLeaderId());

        Acknowledge ack = newViewHandler.onNewView(request);
        responseObserver.onNext(ack);
        responseObserver.onCompleted();
    }
    @Override
    public void prepareCertificatePhase(PrepareCertificate request, StreamObserver<Acknowledge> responseObserver) {
        if (!shouldProcessPhase(responseObserver, request, "PREPARECERTIFICATE")) return;

        String self = nodeState.getSelfNodeId();
        log.info("[{}] Received PrepareCertificate(seq={}, digest={}, prepares={})",
                self, request.getSequence(), request.getDigest(), request.getPreparesCount());

        Acknowledge ack = prepareHandler.onPrepareCertificate(request);
        responseObserver.onNext(ack);
        responseObserver.onCompleted();
    }

    @Override
    public void commitCertificatePhase(CommitCertificate request, StreamObserver<Acknowledge> responseObserver) {
        if (!shouldProcessPhase(responseObserver, request, "COMMIT CERITIFICATE")) return;

        String self = nodeState.getSelfNodeId();
        log.info("[{}] Received CommitCertificate(seq={}, digest={}, commits={})",
                self, request.getSequence(), request.getDigest(), request.getCommitsCount());

        Acknowledge ack = commitHandler.onCommitCertificate(request);
        responseObserver.onNext(ack);
        responseObserver.onCompleted();
    }


    @Override
    public void checkpointProofPhase(CheckpointProofMessage request, StreamObserver<Acknowledge> responseObserver) {
        if (!shouldProcessPhase(responseObserver, request, "CHECKPOINT_PROOF")) return;

        if (!nodeState.isPrimary()) {
            responseObserver.onNext(Acknowledge.newBuilder()
                    .setSuccess(false)
                    .setMessage("NOT_COLLECTOR")
                    .build());
            responseObserver.onCompleted();
            return;
        }

        checkpointService.handleCheckpointProofMessage(request);
        responseObserver.onNext(Acknowledge.newBuilder()
                .setSuccess(true)
                .setMessage("PROOF_ACCEPTED")
                .build());
        responseObserver.onCompleted();
    }

    @Override
    public void checkpointCertificatePhase(CheckpointCertificateBroadcast request, StreamObserver<Acknowledge> responseObserver) {
        if (!shouldProcessPhase(responseObserver, request, "CHECKPOINT_CERT")) return;

        checkpointService.handleCheckpointCertificateBroadcast(request);
        responseObserver.onNext(Acknowledge.newBuilder()
                .setSuccess(true)
                .setMessage("CERT_APPLIED")
                .build());
        responseObserver.onCompleted();
    }

    @Override
    public void getCheckpointState(CheckpointStateRequest request, StreamObserver<CheckpointState> responseObserver) {
        long seq = request.getSequence();
        String digest = request.getDigest();
        try {
            CheckpointState state = checkpointService.serveCheckpointState(seq, digest, request.getRequester());
            if (state != null && !state.getSerializedStateJson().isBlank()) {
                responseObserver.onNext(state);

            } else {

                responseObserver.onNext(CheckpointState.newBuilder()
                        .setSequence(seq)
                        .setDigest(digest == null ? "" : digest)
                        .build());
            }
            responseObserver.onCompleted();
        } catch (Exception e) {

            responseObserver.onError(Status.INTERNAL
                    .withDescription("Failed to serve checkpoint state: " + e.getMessage())
                    .asRuntimeException());
        }
    }




    @Override
    public void onClientReply(
            com.distributedsystems.pbft.proto.ClientReply request,
            io.grpc.stub.StreamObserver<com.distributedsystems.pbft.proto.Acknowledge> responseObserver) {



        com.distributedsystems.pbft.proto.Acknowledge ack =
                com.distributedsystems.pbft.proto.Acknowledge.newBuilder()
                        .setSuccess(true)
                        .setMessage("Reply received")
                        .build();

        responseObserver.onNext(ack);
        responseObserver.onCompleted();
    }

    @Override
    public void adminTimer(TimerControl request, StreamObserver<Acknowledge> responseObserver) {
        if (!shouldProcessPhase(responseObserver, request, "ADMIN TIMER")) return;

        String reason = request.getReason();
        if (reason == null || reason.isBlank()) {
            reason = request.getPause() ? "remote-pause" : "remote-arm";
        }

        try {
            if (request.getPause()) {
                pbftTimerService.pauseTimers(reason);
                nodeState.setParticipating(false);
            } else {
                pbftTimerService.armTimers(reason);
                nodeState.setParticipating(true);
            }
            responseObserver.onNext(Acknowledge.newBuilder().setSuccess(true).build());
            responseObserver.onCompleted();
        } catch (Exception e) {
            responseObserver.onNext(Acknowledge.newBuilder().setSuccess(false).setMessage(e.getMessage()).build());
            responseObserver.onCompleted();
        }
    }


    @Override
    public void adminFlush(com.google.protobuf.Empty request, StreamObserver<Acknowledge> responseObserver) {
        if (!shouldProcessPhase(responseObserver, request, "ADMIN FLUSH")) return;


        try {
            csvScenarioConcurrentService.flushLocalStateTransactional();
            responseObserver.onNext(Acknowledge.newBuilder().setSuccess(true).build());
            responseObserver.onCompleted();
        } catch (Exception e) {
            responseObserver.onNext(Acknowledge.newBuilder().setSuccess(false).setMessage(e.getMessage()).build());
            responseObserver.onCompleted();
        }
    }

}
