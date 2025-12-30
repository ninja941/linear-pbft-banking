package com.distributedsystems.pbft.state;

import com.distributedsystems.pbft.exe.ClusterConfig;
import com.distributedsystems.pbft.model.CheckpointEntity;
import com.distributedsystems.pbft.proto.*;
import com.distributedsystems.pbft.repository.ICheckpointRepository;
import com.distributedsystems.pbft.repository.IClientAccountRepository;
import com.distributedsystems.pbft.service.PhaseHandlers.ViewChangePhaseHandlerImpl;
import jakarta.annotation.PostConstruct;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

@Slf4j
@Data
@ToString
@Component
public class NodeState {

    private final ClusterConfig
            clusterConfig;
    private ViewChangePhaseHandlerImpl viewChangeHandler;

    @Value("${NODE_ID:1}")
    private int nodeId;

    private String selfNodeId;
    private int currentView = 0;
    private boolean isPrimary;
    private long lastSequenceNumber;
    private int lastCommitSequenceNumber;
    private String primaryNodeId;
    private int grpcPort;
    private long lastCheckpointSequenceNumber;

    private List<String> clusterMembers = new ArrayList<>();

    private final Map<Long, List<Prepare>> collectedPrepares = new ConcurrentHashMap<>();
    private final Map<Long, List<Commit>>  collectedCommits  = new ConcurrentHashMap<>();
    private final Map<Long, PrePrepare> prePrepareLog = new ConcurrentHashMap<>();
    private final Map<Long, Prepare>    prepareLog    = new ConcurrentHashMap<>();
    private final Map<Long, Commit>     commitLog     = new ConcurrentHashMap<>();
    private final Map<Long, Integer> prePrepareAckCount = new ConcurrentHashMap<>();
    private final Map<Long, Integer> prepareAckCount    = new ConcurrentHashMap<>();

    private final Map<Long, Set<Prepare>> preparesBySeq = new ConcurrentHashMap<>();
    private final Map<Long, Set<Commit>>  commitsBySeq  = new ConcurrentHashMap<>();

    private final AtomicLong lastSequence = new AtomicLong(0);

    private final Set<Integer> liveNodes = ConcurrentHashMap.newKeySet();
    private final Set<Integer> deadNodes = ConcurrentHashMap.newKeySet();

    private final Map<Long, PrepareCertificate> prepareCertificates = new ConcurrentHashMap<>();
    private final Map<Long, CommitCertificate>  commitCertificates  = new ConcurrentHashMap<>();
    private final Map<Long, Map<String, ViewChange>> viewChangeMessages = new ConcurrentHashMap<>();
    private final Deque<NewViewRecord> newViewHistory = new ArrayDeque<>();
    private final AtomicLong newViewGeneration = new AtomicLong(0);
    private static final int MAX_NEW_VIEW_HISTORY = 16;

    private PrivateKey privateKey;
    private final Map<String, PublicKey> publicKeysByNode = new ConcurrentHashMap<>();
    private final AtomicLong lastProgressTimestamp = new AtomicLong(System.currentTimeMillis());
    private final AtomicLong lastActivityTimestamp = new AtomicLong(System.currentTimeMillis());
    private final AtomicBoolean trafficObserved = new AtomicBoolean(false);
    private final AtomicBoolean awaitingProgress = new AtomicBoolean(false);
    private final AtomicBoolean participatingInCurrentSet = new AtomicBoolean(true);

    private final IClientAccountRepository clientAccountRepository;
    private final ICheckpointRepository checkpointRepository;

    public NodeState(ClusterConfig clusterConfig,
                     IClientAccountRepository clientAccountRepository,
                     ICheckpointRepository checkpointRepository) {
        this.clusterConfig = clusterConfig;
        this.clientAccountRepository = clientAccountRepository;
        this.checkpointRepository = checkpointRepository;
    }

    @Autowired
    public void setViewChangeHandler(@Lazy ViewChangePhaseHandlerImpl viewChangeHandler) {
        this.viewChangeHandler = viewChangeHandler;
    }

    public ViewChangePhaseHandlerImpl getViewChangeHandler() {
        return viewChangeHandler;
    }

    public synchronized long nextSequenceNumber() {
        return ++lastSequenceNumber;
    }

    public String validPrimaryIdForView(long view) {
        List<ClusterConfig.NodeMetaData> rotation = clusterConfig.getNodes();
        if (!liveNodes.isEmpty() && liveNodes.size() < rotation.size()) {
            List<ClusterConfig.NodeMetaData> filtered = rotation.stream()
                    .filter(meta -> liveNodes.contains(meta.getId()))
                    .toList();
            if (!filtered.isEmpty()) {
                rotation = filtered;
            }
        }

        int total = rotation.size();
        int idx = (int) Math.floorMod(view, total);
        int leaderId = rotation.get(idx).getId();
        return "node-" + leaderId;
    }
    public boolean amPrimaryForView(long view) {
        String expectedLeader = validPrimaryIdForView(view);
        return expectedLeader != null && expectedLeader.equals(getSelfNodeId());
    }

    public long nextSequence() {
        return lastSequence.incrementAndGet();
    }

    public long reserveSequences(int count) {
        if (count <= 0) return lastSequence.get();
        long previous = lastSequence.getAndAdd(count);
        return previous + 1;
    }

    public int quorumSize() {
        return 2 * clusterConfig.getByzantineNodes() + 1;
    }

    public Optional<PrePrepare> getPrePrepareLog(long seq) {
        return Optional.ofNullable(prePrepareLog.get(seq));
    }

    public Map<Long, PrePrepare> getPrePrepareLogMap() {
        return prePrepareLog;
    }

    public void putPrePrepare(PrePrepare m) {
        prePrepareLog.put(m.getSequence(), m);
        markActivity();
    }

    public String getSelfNodeId() {
        return selfNodeId != null ? selfNodeId : ("node-" + nodeId);
    }

    public List<String> getClusterMembers() {
        if (clusterConfig == null) return Collections.emptyList();
        List<String> members = new ArrayList<>();
        clusterConfig.getNodes().forEach(n -> members.add(n.getHost() + ":" + n.getGrpcPort()));
        return members;
    }

    public Set<Prepare> preparesFor(long seq) {
        return preparesBySeq.computeIfAbsent(seq, k -> Collections.synchronizedSet(new HashSet<>()));
    }

    public Set<Commit> commitsFor(long seq) {
        return commitsBySeq.computeIfAbsent(seq, k -> Collections.synchronizedSet(new HashSet<>()));
    }

    public Map<String, ViewChange> viewChangesFor(long view) {
        return viewChangeMessages.computeIfAbsent(view, v -> new ConcurrentHashMap<>());
    }

    public void clearViewChanges(long view) {
        viewChangeMessages.remove(view);
    }

    public synchronized void clearViewChangesAtOrAbove(long viewThresholdInclusive) {
        viewChangeMessages.keySet().removeIf(v -> v >= viewThresholdInclusive);
    }

    public synchronized void clearNewViewMessages() {
        newViewHistory.clear();
    }

    public synchronized void rememberNewView(NewView newView) {
        if (newView == null) return;
        long generation = newViewGeneration.get();
        newViewHistory.addLast(new NewViewRecord(newView, generation));
        pruneNewViewHistory();
    }

    public List<NewViewSnapshot> snapshotNewViewHistory() {
        return snapshotNewViewHistory(false);
    }

    public synchronized List<NewViewSnapshot> snapshotNewViewHistory(boolean includeHistory) {
        if (newViewHistory.isEmpty()) return Collections.emptyList();
        long activeGeneration = newViewGeneration.get();
        List<NewViewSnapshot> snapshots = new ArrayList<>();
        for (NewViewRecord record : newViewHistory) {
            if (!includeHistory && record.generation != activeGeneration) continue;
            snapshots.add(NewViewSnapshot.from(record));
        }
        return snapshots;
    }

    private void pruneNewViewHistory() {
        while (newViewHistory.size() > MAX_NEW_VIEW_HISTORY) {
            newViewHistory.removeFirst();
        }
    }

    public synchronized void advanceNewViewGeneration(boolean dropHistory) {
        newViewGeneration.incrementAndGet();
        if (dropHistory) {
            newViewHistory.clear();
        }
    }

    public List<ClusterConfig.NodeMetaData> peersExcludingSelf() {
        List<ClusterConfig.NodeMetaData> peers = new ArrayList<>();
        List<ClusterConfig.NodeMetaData> nodes = clusterConfig != null ? clusterConfig.getNodes() : null;
        if (nodes == null) return peers;
        for (ClusterConfig.NodeMetaData n : nodes) {
            if (n == null) continue;
            if (n.getId() == nodeId) continue;
            if (!liveNodes.isEmpty() && !liveNodes.contains(n.getId())) continue;
            peers.add(n);
        }
        return peers;
    }

    public Optional<ClusterConfig.NodeMetaData> nodeInfo(int id) {
        return clusterConfig.getNodes().stream().filter(n -> n.getId() == id).findFirst();
    }

    public Optional<ClusterConfig.NodeMetaData> nodeInfo(String nodeIdStr) {
        try {
            String s = nodeIdStr.startsWith("node-") ? nodeIdStr.substring(5) : nodeIdStr;
            int id = Integer.parseInt(s);
            return nodeInfo(id);
        } catch (NumberFormatException e) {
            log.error("Invalid nodeId format: {}", nodeIdStr);
            return Optional.empty();
        }
    }

    @PostConstruct
    public void init() {
        clusterConfig.getNodes().forEach(n -> liveNodes.add(n.getId()));
        deadNodes.clear();
        participatingInCurrentSet.set(true);
        selfNodeId = "node-" + nodeId;
        refreshLeadershipMetadata();
        log.info("[{}] Cluster nodes loaded: {}", selfNodeId,
                clusterConfig.getNodes().stream().map(ClusterConfig.NodeMetaData::getId).toList());
    }

    public synchronized void setCurrentView(int currentView) {
        installView(currentView);
    }

    private void refreshLeadershipMetadata() {
        String expectedLeader = validPrimaryIdForView(currentView);
        this.isPrimary = expectedLeader.equals(getSelfNodeId());

        this.primaryNodeId = nodeInfo(expectedLeader)
                .map(meta -> meta.getHost() + ":" + meta.getGrpcPort())
                .orElse(null);

        log.info("[{}] View={} leader={} primaryEndpoint={} (amPrimary={})",
                getSelfNodeId(), currentView, expectedLeader, primaryNodeId, isPrimary);
    }

    public synchronized void markAlive(int nodeId) {
        deadNodes.remove(nodeId);
        liveNodes.add(nodeId);
        if (this.nodeId == nodeId) {
            participatingInCurrentSet.set(true);
        }
    }

    public synchronized void markDead(int nodeId) {
        liveNodes.remove(nodeId);
        deadNodes.add(nodeId);
        if (this.nodeId == nodeId) {
            participatingInCurrentSet.set(false);
        }
    }

    public Set<Integer> getLiveNodes() { return Collections.unmodifiableSet(liveNodes); }
    public Set<Integer> getDeadNodes() { return Collections.unmodifiableSet(deadNodes); }
    public boolean isAlive(int nodeId) { return liveNodes.contains(nodeId); }
    public boolean isDead(int nodeId) { return deadNodes.contains(nodeId); }

    public int getByzantineNodesCount() { return clusterConfig.getByzantineNodes(); }

    public int getBackupAckCount() {
        int configuredNodes = Math.max(1, totalNodes());
        int toleratedFaults = Math.min(getByzantineNodesCount(), configuredNodes - 1);
        int backupsNeeded = configuredNodes - toleratedFaults - 1;
        return Math.max(1, backupsNeeded);
    }

    public void addPrePrepareAck(long sequence, int count) { prePrepareAckCount.merge(sequence, count, Integer::sum); }
    public void addPrepareAck(long sequence, int count)    { prepareAckCount.merge(sequence, count, Integer::sum); }

    public int getPrePrepareAckCount(long sequenceNumber) { return prePrepareAckCount.getOrDefault(sequenceNumber, 0); }
    public int getPrepareAckCount(long sequenceNumber)    { return prepareAckCount.getOrDefault(sequenceNumber, 0); }

    public void clearAckCounters(long sequenceNumber) {
        prePrepareAckCount.remove(sequenceNumber);
        prepareAckCount.remove(sequenceNumber);
    }

    public int totalNodes() { return clusterConfig.getTotalNodes(); }

    public synchronized void replaceLiveSet(Set<Integer> lives) {
        if (clusterConfig == null) return;

        Set<Integer> allConfigured = clusterConfig.getNodes()
                .stream()
                .map(ClusterConfig.NodeMetaData::getId)
                .collect(Collectors.toSet());

        Set<Integer> effective = new LinkedHashSet<>();
        if (lives != null && !lives.isEmpty()) {
            effective.addAll(lives);
            effective.retainAll(allConfigured);
        } else {
            effective.addAll(allConfigured);
        }

        liveNodes.clear();
        liveNodes.addAll(effective);

        deadNodes.clear();
        Set<Integer> newDead = new LinkedHashSet<>(allConfigured);
        newDead.removeAll(effective);
        deadNodes.addAll(newDead);

        boolean selfLive = effective.contains(nodeId);
        participatingInCurrentSet.set(selfLive);

        log.info("[{}] Live set replaced = {}", getSelfNodeId(), liveNodes);
        log.info("[{}] Dead nodes now = {}", getSelfNodeId(), deadNodes);
        refreshLeadershipMetadata();
    }

    public synchronized void clearEphemeralForNextSet() {
        prePrepareLog.clear();
        prepareLog.clear();
        commitLog.clear();

        preparesBySeq.clear();
        commitsBySeq.clear();
        viewChangeMessages.clear();
        trafficObserved.set(false);
        awaitingProgress.set(false);

        collectedPrepares.clear();
        collectedCommits.clear();

        prePrepareAckCount.clear();
        prepareAckCount.clear();

        prepareCertificates.clear();
        commitCertificates.clear();

        lastSequenceNumber = 0;
        lastCommitSequenceNumber = 0;
        lastSequence.set(0);
        lastExecutedSequenceNumber = 0L;

        log.info("[{}] Cleared in-memory PBFT state for next set.", getSelfNodeId());
    }

    private int lastCheckpointSeq = 0;
    private String lastCheckpointLabel;

    public synchronized void markCheckpointSequenceNumber(int seq) {
        this.lastCheckpointSeq = seq;
        log.info("[{}] Marked checkpoint at seq={}", getSelfNodeId(), seq);
    }

    public synchronized int getLastCheckpointSequenceNumber() {
        return lastCheckpointSeq;
    }

    public synchronized long getLowWatermark() {
        return Math.max(0, lastCheckpointSeq);
    }

    private static final long WATERMARK_WINDOW = 50L;

    public synchronized long getHighWatermark() {
        return getLowWatermark() + WATERMARK_WINDOW;
    }

    public synchronized void setLastCheckpointLabel(String label) {
        this.lastCheckpointLabel = label;
    }

    public synchronized String getLastCheckpointLabel() {
        return lastCheckpointLabel;
    }

    private String currentLeaderId;

    public synchronized void setNextSequence(long next) {
        this.lastSequenceNumber = Math.max(0, next - 1);
        this.lastSequence.set(Math.max(0, next - 1));
    }

    public synchronized void setLastCommitSequenceNumber(int v) {
        this.lastCommitSequenceNumber = Math.max(0, v);
    }

    public synchronized void resetExecutionState() {

        collectedPrepares.clear();
        collectedCommits.clear();
        preparesBySeq.clear();
        commitsBySeq.clear();
        prePrepareAckCount.clear();
        prepareAckCount.clear();
        prepareCertificates.clear();
        commitCertificates.clear();
        viewChangeMessages.clear();

        lastCommitSequenceNumber = 0;
        lastSequenceNumber = 0;
        lastSequence.set(0);
        lastCheckpointSeq = 0;
        lastCheckpointLabel = null;

        prePrepareLog.clear();
        prepareLog.clear();
        commitLog.clear();

        markProgress();
    }

    public synchronized void updateLeader(String leaderId) {
        this.currentLeaderId = leaderId;
    }

    public synchronized void resetEphemeralState() {
        try {
            advanceNewViewGeneration(false);
            this.currentLeaderId = null;
            setCurrentView(0);

            clearEphemeralForNextSet();
            markProgress();

            inProgressViews.clear();
            lastInitiatedView = -1;

            try {
                started = false;
                if (startedAtMs != null) startedAtMs.set(0L);
            } catch (Exception ignored) { }

        } catch (Exception e) {
        }
    }

    public void markProgress() {
        long now = System.currentTimeMillis();
        lastProgressTimestamp.set(now);
        lastActivityTimestamp.set(now);
        awaitingProgress.set(false);
    }

    public void markActivity() {
        lastActivityTimestamp.set(System.currentTimeMillis());
    }

    public void markTrafficObserved() {
        trafficObserved.set(true);
        markActivity();
        awaitingProgress.set(true);
    }

    public void noteOutstandingWork() {
        awaitingProgress.set(true);
        markActivity();
    }

    public long getLastProgressTimestamp() {
        return lastProgressTimestamp.get();
    }

    public long getLastActivityTimestamp() {
        return lastActivityTimestamp.get();
    }

    public boolean hasProcessedRequests() {
        return trafficObserved.get() || lastSequenceNumber > 0 || !prePrepareLog.isEmpty();
    }

    public boolean hasOutstandingProgress() {
        if (awaitingProgress.get()) return true;
        int committed = getLastCommitSequenceNumber();
        long highestPrePrepare = highestIndex(prePrepareLog.keySet(), committed);
        long highestPreparedCertificate = highestIndex(prepareCertificates.keySet(), committed);
        long highestCommitCertificate = highestIndex(commitCertificates.keySet(), committed);
        long highestPrepareQuorum = highestIndex(preparesBySeq.keySet(), committed);
        long highestCommitQuorum = highestIndex(commitsBySeq.keySet(), committed);

        return highestPrePrepare > committed
                || highestPreparedCertificate > committed
                || highestCommitCertificate > committed
                || highestPrepareQuorum > committed
                || highestCommitQuorum > committed;
    }

    private long highestIndex(Collection<Long> source, long fallback) {
        return source.stream().mapToLong(Long::longValue).max().orElse(fallback);
    }

    private long lastInitiatedView = -1;
    private final Set<Long> inProgressViews = ConcurrentHashMap.newKeySet();

    public synchronized void installView(int v) {
        this.currentView = v;
        refreshLeadershipMetadata();
        markActivity();
        markProgress();
        clearViewChangeInProgressAtOrBelow(v);
        if (lastInitiatedView < v) {
            lastInitiatedView = v;
        }
    }

    public boolean isViewChangeInProgress(long view) {
        return inProgressViews.contains(view);
    }

    public void markViewChangeInProgress(long view) {
        inProgressViews.add(view);
    }

    public synchronized boolean tryStartViewChange(long nextView) {
        if (nextView <= currentView) return false;
        if (nextView < lastInitiatedView) return false;

        if (nextView == lastInitiatedView && inProgressViews.contains(nextView)) {
            return false;
        }

        lastInitiatedView = nextView;
        inProgressViews.add(nextView);
        return true;
    }

    public void clearViewChangeInProgress(long view) {
        inProgressViews.remove(view);
    }

    public void clearViewChangeInProgressAtOrBelow(long view) {
        inProgressViews.removeIf(v -> v <= view);
    }


    public boolean isDead(String nodeId) {
        if (nodeId == null) return false;
        return deadNodes.contains(parseNodeId(nodeId));
    }

    public boolean isParticipating() {
        return participatingInCurrentSet.get();
    }

    public void setParticipating(boolean participating) {
        boolean previous = participatingInCurrentSet.getAndSet(participating);
        if (previous != participating) {
            log.info("[{}] Participation flag set to {}", getSelfNodeId(), participating);
        }
    }

    private int parseNodeId(String nodeId) {
        try {
            if (nodeId.startsWith("node-")) {
                return Integer.parseInt(nodeId.substring(5));
            }
            return Integer.parseInt(nodeId);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    public boolean isLive(String nodeId) {
        try {
            if (nodeId == null) return false;
            String idStr = nodeId.startsWith("node-") ? nodeId.substring(5) : nodeId;
            int id = Integer.parseInt(idStr);
            return liveNodes.contains(id);
        } catch (Exception e) {
            return false;
        }
    }

    public void markLive(String nodeId) {
        try {
            String idStr = nodeId.startsWith("node-") ? nodeId.substring(5) : nodeId;
            int id = Integer.parseInt(idStr);
            liveNodes.add(id);
            deadNodes.remove(id);
            if (this.nodeId == id) {
                participatingInCurrentSet.set(true);
            }
            log.info("[{}] Marked {} live.", getSelfNodeId(), nodeId);
        } catch (Exception ignored) {}
    }

    public void markDead(String nodeId) {
        try {
            String idStr = nodeId.startsWith("node-") ? nodeId.substring(5) : nodeId;
            int id = Integer.parseInt(idStr);
            liveNodes.remove(id);
            deadNodes.add(id);
            if (this.nodeId == id) {
                participatingInCurrentSet.set(false);
            }
            log.info("[{}] Marked {} dead.", getSelfNodeId(), nodeId);
        } catch (Exception ignored) {}
    }

    public List<ClusterConfig.NodeMetaData> livePeersExcludingSelf() {
        List<ClusterConfig.NodeMetaData> peers = new ArrayList<>();
        List<ClusterConfig.NodeMetaData> nodes = clusterConfig != null ? clusterConfig.getNodes() : null;
        if (nodes == null) return peers;
        for (ClusterConfig.NodeMetaData n : nodes) {
            if (n == null) continue;
            if (n.getId() != nodeId && isAlive(n.getId())) {
                peers.add(n);
            }
        }
        return peers;
    }
    public void restoreBalances(Map<String, Long> snapshot) {
        try {
            if (clientAccountRepository == null) {
                return;
            }

            var accounts = clientAccountRepository.findAll();
            for (var acc : accounts) {
                Long val = snapshot.get(acc.getName());
                if (val != null) {
                    acc.setBalance(val);
                }
            }
            clientAccountRepository.saveAllAndFlush(accounts);
        } catch (Exception e) {
        }
    }

    public String loadSerializedStateForCheckpoint(long seq) {
        var cp = checkpointRepository.findBySequenceNumber(seq);
        return cp.map(CheckpointEntity::getSerializedState).orElse(null);
    }
    public long getLastStableCheckpointSeq() {
        try {
            return checkpointRepository.findTopByOrderBySequenceNumberDesc()
                    .map(CheckpointEntity::getSequenceNumber)
                    .orElse(0L); // default 0 if no checkpoint exists yet
        } catch (Exception e) {
            return 0L;
        }
    }


    private boolean crashedLeader = false;

    public void markAsCrashedLeader() {
        this.crashedLeader = true;
    }

    private long lastExecutedSequenceNumber = 0L;

    public long getLastExecutedSequenceNumber() { return lastExecutedSequenceNumber; }
    public void setLastExecutedSequenceNumber(long seq) { this.lastExecutedSequenceNumber = seq; }
    private volatile boolean started = false;

    public boolean hasStarted() {
        return started;
    }

    public void markStarted() {
        if (!started) {
            started = true;
        }
        startedAtMs.set(System.currentTimeMillis());
        markProgress();
    }

    private final AtomicLong startedAtMs = new AtomicLong(0L);
    public long getStartedAtMs() { return startedAtMs.get(); }


    private static final class NewViewRecord {
        private final NewView message;
        private final long recordedAtMs;
        private final long generation;

        private NewViewRecord(NewView message, long generation) {
            this.message = message;
            this.recordedAtMs = System.currentTimeMillis();
            this.generation = generation;
        }
    }

    public record NewViewSnapshot(NewView newView, Instant recordedAt, long generation) {
        private static NewViewSnapshot from(NewViewRecord record) {
            return new NewViewSnapshot(record.message, Instant.ofEpochMilli(record.recordedAtMs), record.generation);
        }
    }
}
