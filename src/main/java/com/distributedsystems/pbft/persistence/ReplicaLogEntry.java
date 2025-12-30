package com.distributedsystems.pbft.persistence;

import com.distributedsystems.pbft.model.ReplicaLogEntity;
import com.distributedsystems.pbft.repository.IReplicatLogRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DeadlockLoserDataAccessException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class ReplicaLogEntry {

    private static final int MAX_RETRIES = 6;
    private static final long BASE_BACKOFF_MS = 12L;

    private final IReplicatLogRepository replicatLogRepository;

    public boolean exists(long seq) {
        try {
            return replicatLogRepository.existsById(seq);
        } catch (Exception e) {
            log.error("[ReplicaLog] exists(seq={}) failed: {}", seq, e.getMessage(), e);
            return false;
        }
    }

    @Transactional(Transactional.TxType.REQUIRES_NEW)
    public void upsert(long seq, int view, String digest,
                       ReplicaLogEntity.Phase phase, boolean approved,
                       String payload, String prePrepareDigest, String prePreparePayload) {
        upsert(seq, view, digest, phase, approved, payload, prePrepareDigest, prePreparePayload, null);
    }

    @Transactional(Transactional.TxType.REQUIRES_NEW)
    public void upsert(long seq, int view, String digest,
                       ReplicaLogEntity.Phase phase, boolean approved,
                       String payload, String prePrepareDigest, String prePreparePayload,
                       String execResult) {

        synchronized (("LOG_SEQ_" + seq).intern()) {
            int attempt = 0;
            while (true) {
                try {
                    Optional<ReplicaLogEntity> opt = replicatLogRepository.findById(seq);
                    if (opt.isPresent()) {
                        ReplicaLogEntity ex = opt.get();
                        boolean updated = false;

                        if (ex.getPhase() == null || phase.ordinal() > ex.getPhase().ordinal()) {
                            ex.setPhase(phase);
                            updated = true;
                        }
                        boolean belowExecutePhase = ex.getPhase() == null
                                || ex.getPhase().ordinal() <= ReplicaLogEntity.Phase.PREPARED.ordinal();
                        boolean newerView = view >= ex.getViewNumber();

                        if (digest != null) {
                            if (ex.getDigest() == null) {
                                ex.setDigest(digest);
                                updated = true;
                            } else if (!digest.equals(ex.getDigest())) {
                                if (belowExecutePhase && newerView) {
                                    ex.setDigest(digest);
                                    updated = true;
                                }
                            }
                        }
                        if (!ex.isApproved() && approved) {
                            ex.setApproved(true);
                            updated = true;
                        }
                        if (payload != null && (ex.getPayload() == null || !payload.equals(ex.getPayload()))) {
                            ex.setPayload(payload);
                            updated = true;
                        }
                        if (prePrepareDigest != null) {
                            if (ex.getPrePrepareDigest() == null) {
                                ex.setPrePrepareDigest(prePrepareDigest);
                                updated = true;
                            } else if (!prePrepareDigest.equals(ex.getPrePrepareDigest())) {
                                if (belowExecutePhase && newerView) {
                                    ex.setPrePrepareDigest(prePrepareDigest);
                                    updated = true;
                                }
                            }
                        }
                        if (prePreparePayload != null) {
                            if (ex.getPrePreparePayload() == null) {
                                ex.setPrePreparePayload(prePreparePayload);
                                updated = true;
                            } else if (!prePreparePayload.equals(ex.getPrePreparePayload())) {
                                if (belowExecutePhase && newerView) {
                                    ex.setPrePreparePayload(prePreparePayload);
                                    updated = true;
                                }
                            }
                        }
                        if (execResult != null && (ex.getExecResult() == null || !execResult.equals(ex.getExecResult()))) {
                            ex.setExecResult(execResult);
                            updated = true;
                        }

                        if (updated) {
                            if (view > ex.getViewNumber()) ex.setViewNumber(view);
                            ex.setLastUpdated(Instant.now());
                            replicatLogRepository.saveAndFlush(ex);
                        }
                        return;
                    }

                    ReplicaLogEntity e = ReplicaLogEntity.builder()
                            .sequenceNumber(seq)
                            .viewNumber(view)
                            .digest(digest)
                            .phase(phase)
                            .approved(approved)
                            .payload(payload)
                            .prePrepareDigest(prePrepareDigest)
                            .prePreparePayload(prePreparePayload)
                            .execResult(execResult)
                            .lastUpdated(Instant.now())
                            .build();
                    replicatLogRepository.saveAndFlush(e);
                    return;

                } catch (DataIntegrityViolationException dup) {
                } catch (ObjectOptimisticLockingFailureException |
                         DeadlockLoserDataAccessException |
                         CannotAcquireLockException e) {
                    if (++attempt > MAX_RETRIES) {
                        return;
                    }
                    long backoff = BASE_BACKOFF_MS * (1L << (attempt - 1));
                    try {
                        Thread.sleep(backoff);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                } catch (Exception e) {
                    return;
                }
            }
        }
    }

    @Transactional(Transactional.TxType.REQUIRES_NEW)
    public void markCheckpoint(String label, long seq) {
        try {
            ReplicaLogEntity e = replicatLogRepository.findById(seq).orElseGet(() ->
                    ReplicaLogEntity.builder()
                            .sequenceNumber(seq)
                            .viewNumber(0)
                            .phase(ReplicaLogEntity.Phase.EXECUTED)
                            .approved(true)
                            .lastUpdated(Instant.now())
                            .build()
            );
            e.setPhase(ReplicaLogEntity.Phase.EXECUTED);
            e.setApproved(true);
            if (label != null && !label.isBlank()) {
                String checkpointMarker = "CHECKPOINT=" + label;
                String existingResult = e.getExecResult();
                if (existingResult == null || existingResult.isBlank()) {
                    e.setExecResult(checkpointMarker);
                } else if (!existingResult.contains(checkpointMarker)) {
                    e.setExecResult(existingResult + " | " + checkpointMarker);
                }
            }
            e.setLastUpdated(Instant.now());
            replicatLogRepository.saveAndFlush(e);

        } catch (Exception ex) {
        }
    }

    @Transactional(Transactional.TxType.REQUIRES_NEW)
    public void trimToLatestCheckpoint() {
        try {
            var latest = replicatLogRepository.findAll().stream()
                    .filter(e -> e.getPayload() != null && e.getPayload().contains("checkpoint"))
                    .map(ReplicaLogEntity::getSequenceNumber)
                    .max(Long::compareTo);
            if (latest.isEmpty()) return;

            long keep = latest.get();
            replicatLogRepository.findAll().stream()
                    .filter(e -> e.getSequenceNumber() < keep)
                    .forEach(e -> replicatLogRepository.deleteById(e.getSequenceNumber()));

        } catch (Exception e) {
        }
    }

    @Transactional
    public void clearAllCheckpoints() {
        try {
            replicatLogRepository.deleteAll();
        } catch (Exception e) {
        }
    }
}
