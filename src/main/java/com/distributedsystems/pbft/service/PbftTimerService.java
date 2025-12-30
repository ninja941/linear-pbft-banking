package com.distributedsystems.pbft.service;

import com.distributedsystems.pbft.service.PhaseHandlers.ViewChangePhaseHandlerImpl;
import com.distributedsystems.pbft.state.NodeState;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@Service
@RequiredArgsConstructor
public class PbftTimerService {

    private final NodeState nodeState;
    private final ViewChangePhaseHandlerImpl viewChangeHandler;
    private final ByzantineService byzantineService;

    @Value("${pbft.timers.progress-timeout-ms:5000}")
    private volatile long progressTimeoutMs;

    @Value("${pbft.timers.activity-timeout-ms:3000}")
    private volatile long activityTimeoutMs;

    @Value("${pbft.timers.startup-grace-ms:10000}")
    private long startupGraceMs;

    private ScheduledExecutorService scheduler;
    private long defaultProgressTimeoutMs;
    private long defaultActivityTimeoutMs;
    private long startedAt;
    private long outstandingSince;
    private final AtomicBoolean timersArmed = new AtomicBoolean(true);
    private volatile String timerStateLabel = "startup";
    private final AtomicBoolean forceActivityChecks = new AtomicBoolean(false);
    private final AtomicLong lastCrashView = new AtomicLong(-1);

    @PostConstruct
    void start() {
        defaultProgressTimeoutMs = progressTimeoutMs;
        defaultActivityTimeoutMs = activityTimeoutMs;

        long pollInterval = Math.max(250L, Math.min(progressTimeoutMs, activityTimeoutMs) / 2);
        ThreadFactory tf = r -> {
            Thread t = new Thread(r, "pbft-timer");
            t.setDaemon(true);
            return t;
        };
        scheduler = Executors.newSingleThreadScheduledExecutor(tf);
        scheduler.scheduleWithFixedDelay(this::runChecks, pollInterval, pollInterval, TimeUnit.MILLISECONDS);
        startedAt = System.currentTimeMillis();
        log.info("[{}] PBFT timers armed: progress={}ms activity={}ms poll={}ms",
                nodeState.getSelfNodeId(), progressTimeoutMs, activityTimeoutMs, pollInterval);
    }

    @PreDestroy
    void stop() {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
    }

    private void runChecks() {
        try {
            if (!timersArmed.get()) return;

            long now = System.currentTimeMillis();
            boolean beyondGrace = now - startedAt > startupGraceMs;
            if (!beyondGrace) return;

            boolean force = forceActivityChecks.get();

            if (!nodeState.hasStarted() && !force) return;

            if (!nodeState.isParticipating()) return;

            boolean hasProcessed = nodeState.hasProcessedRequests();
            if (!hasProcessed && !force) {
                return;
            }
            maybeTriggerCrashViewChange();

            boolean outstanding = nodeState.hasOutstandingProgress();
            if (!outstanding) {
                outstandingSince = 0L;
            } else if (outstandingSince == 0L) {
                outstandingSince = System.currentTimeMillis();
            }

            long sinceProgress = now - nodeState.getLastProgressTimestamp();
            if (sinceProgress < Math.max(500L, progressTimeoutMs / 3)) {
                return;
            }

            if (progressTimeoutMs > 0 && outstanding) {
                checkProgressTimeout();
            }
            if (activityTimeoutMs > 0) {
                checkActivityTimeout(outstanding);
            }
        } catch (Exception e) {
            log.error("[{}] Timer check failed: {}", nodeState.getSelfNodeId(), e.getMessage(), e);
        }
    }

    private void checkProgressTimeout() {
        if (nodeState.isPrimary()) return;
        long baseline = Math.max(nodeState.getLastProgressTimestamp(), outstandingSince);
        long idle = System.currentTimeMillis() - baseline;
        if (idle >= progressTimeoutMs) {
            viewChangeHandler.requestViewChange("No commit progress for " + Duration.ofMillis(idle));
        }
    }

    private void checkActivityTimeout(boolean outstanding) {
        if (nodeState.isPrimary()) return;

        if (!forceActivityChecks.get() && outstanding) return;

        long idle = System.currentTimeMillis() - nodeState.getLastActivityTimestamp();
        if (idle >= activityTimeoutMs) {
            viewChangeHandler.requestViewChange("No PBFT traffic for " + Duration.ofMillis(idle));
        }
    }

    public void resetAfterNewView() {
        outstandingSince = 0L;
        nodeState.markProgress();
        lastCrashView.set(-1);
        log.debug("[{}] Execution timers reset after NEW-VIEW install", nodeState.getSelfNodeId());
    }

    public boolean areTimersArmed() {
        return timersArmed.get();
    }

    public void armTimers(String reason) {
        if (timersArmed.compareAndSet(false, true)) {
            outstandingSince = 0L;
            timerStateLabel = (reason == null || reason.isBlank()) ? "manual-arm" : reason;
            log.info("[{}] PBFT timers resumed ({})", nodeState.getSelfNodeId(), timerStateLabel);
        } else if (reason != null && !reason.isBlank()) {
            timerStateLabel = reason;
        }
    }

    public void pauseTimers(String reason) {
        if (timersArmed.compareAndSet(true, false)) {
            outstandingSince = 0L;
            timerStateLabel = (reason == null || reason.isBlank()) ? "manual-pause" : reason;
            log.info("[{}] PBFT timers paused ({})", nodeState.getSelfNodeId(), timerStateLabel);
        } else if (reason != null && !reason.isBlank()) {
            timerStateLabel = reason;
        }
    }

    public Duration recommendedClientMaxWait(Duration fallback) {
        long baselineMs = Math.max(progressTimeoutMs, activityTimeoutMs);
        long fallbackMs = (fallback == null || fallback.isZero() || fallback.isNegative())
                ? 0L : fallback.toMillis();
        long candidate = Math.max(fallbackMs, baselineMs);
        if (candidate <= 0L) {
            candidate = Math.max(1000L, baselineMs);
        }
        return Duration.ofMillis(candidate);
    }

    public synchronized void overrideActivityTimeout(Duration timeout, String reason) {
        long newMs = coerceTimeout(timeout, defaultActivityTimeoutMs);
        if (newMs == activityTimeoutMs) return;
        activityTimeoutMs = newMs;
        log.warn("[{}] Activity-timeout override → {} ms ({})",
                nodeState.getSelfNodeId(), activityTimeoutMs, reason);
    }

    public synchronized void resetActivityTimeout(String reason) {
        if (activityTimeoutMs == defaultActivityTimeoutMs) return;
        activityTimeoutMs = defaultActivityTimeoutMs;
        log.info("[{}] Activity-timeout reset → {} ms ({})",
                nodeState.getSelfNodeId(), activityTimeoutMs,
                reason == null ? "override cleared" : reason);
    }

    public void setForceActivityChecks(boolean enable, String reason) {
        boolean previous = forceActivityChecks.getAndSet(enable);
        if (enable && !previous) {
            log.warn("[{}] Activity-timeout guard disabled → forcing checks ({})",
                    nodeState.getSelfNodeId(), reason);
        } else if (!enable && previous) {
            log.info("[{}] Activity-timeout guard restored ({})",
                    nodeState.getSelfNodeId(), reason);
        }
    }

    private long coerceTimeout(Duration candidate, long fallbackMs) {
        long value = (candidate == null) ? fallbackMs : candidate.toMillis();
        if (value <= 0L) value = fallbackMs;
        return Math.max(250L, value);
    }

    public long getProgressTimeoutMs() {
        return progressTimeoutMs;
    }

    public long getActivityTimeoutMs() {
        return activityTimeoutMs;
    }

    private void maybeTriggerCrashViewChange() {
        if (nodeState.isPrimary()) return;
        long currentView = nodeState.getCurrentView();
        long last = lastCrashView.get();
        if (last == currentView) return;

        String leaderId = nodeState.validPrimaryIdForView(currentView);
        if (leaderId == null) return;
        if (!byzantineService.isCrashed(leaderId)) return;

        if (lastCrashView.compareAndSet(last, currentView)) {
            log.warn("[{}] Detected crashed primary {} for view {} → requesting next view",
                    nodeState.getSelfNodeId(), leaderId, currentView);
            viewChangeHandler.requestViewChange(currentView + 1,
                    "Primary " + leaderId + " crashed (timer)");
        }
    }
}
