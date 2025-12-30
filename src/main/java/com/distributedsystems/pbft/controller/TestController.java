package com.distributedsystems.pbft.controller;

import com.distributedsystems.pbft.client.ClientRequestDTO;
import com.distributedsystems.pbft.exe.ClusterConfig;
import com.distributedsystems.pbft.model.ReadLogEntity;
import com.distributedsystems.pbft.model.ReplicaLogEntity;
import com.distributedsystems.pbft.proto.ClientRequest;
import com.distributedsystems.pbft.proto.NewView;
import com.distributedsystems.pbft.proto.PrePrepare;
import com.distributedsystems.pbft.proto.PreparedEntry;
import com.distributedsystems.pbft.service.CheckpointService;
import com.distributedsystems.pbft.service.ClientRequestAuthenticator;
import com.distributedsystems.pbft.service.PbftServiceImpl;
import com.distributedsystems.pbft.util.CSVHandler.CSVScenarioConcurrentService;
import com.distributedsystems.pbft.util.CSVHandler.CSVScenarioRunner;
import com.distributedsystems.pbft.repository.IReadLogRepository;
import com.distributedsystems.pbft.repository.IReplicatLogRepository;
import com.distributedsystems.pbft.repository.IClientAccountRepository;
import com.distributedsystems.pbft.state.NodeState;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Lazy
public class TestController {

    private static final Logger log = LoggerFactory.getLogger(TestController.class);
    private static final List<String> DEFAULT_ACCOUNT_COLUMNS = List.of("A","B","C","D","E","F","G","H","I","J");
    private static final TypeReference<List<AccountSnapshot>> ACCOUNT_LIST_TYPE = new TypeReference<>() {};
    private static final long BALANCE_SEQ_BASE = 9_000_000_000_000L;
    private static final Pattern CLIENT_ALIAS = Pattern.compile("csv-(\\d+).*", Pattern.CASE_INSENSITIVE);
    private final PbftServiceImpl pbftService;
    private final IReplicatLogRepository replicaLogRepository;
    private final IReadLogRepository readLogRepository;
    private final IClientAccountRepository accountRepository;
    private final NodeState nodeState;

    private final CSVScenarioConcurrentService csvScenarioService;
    private final CheckpointService checkpointService;
    private final ClientRequestAuthenticator clientRequestAuthenticator;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();
    @PostMapping("/submitClientRequest")
    public String submitClientRequest(@RequestBody ClientRequestDTO dto) {
        try {
            ClientRequest request = clientRequestAuthenticator.sign(
                    ClientRequest.newBuilder()
                            .setClientId(dto.getClientId())
                            .setFromAccount(dto.getFromAccount())
                            .setToAccount(dto.getToAccount())
                            .setAmount(dto.getAmount())
                            .setOperation(dto.getOperation())
                            .setTimestamp(dto.getTimestamp())
            );

            pbftService.forwardRequestToPrimary(request);
            return "Client request accepted";
        } catch (Exception e) {
            log.error(" Error while submitting client request", e);
            return "Failed: " + e.getMessage();
        }
    }


    private final CSVScenarioRunner csvRunner;


    @PostMapping("/runCSVFile")
    public String runCsvFile(@RequestParam String fileName) {
        try {
            log.info("Triggered Client Orchestation: {}", fileName);
            csvRunner.runScenario(fileName);
            return "CSV scenario executed successfully: " + fileName;
        } catch (Exception e) {
            log.error("Failed to execute CSV file {}: {}", fileName, e.getMessage(), e);
            return "Error executing CSV: " + e.getMessage();
        }
    }

    @PostMapping("/runCSVConcurrent")
    public String runCsvConcurrent(@RequestParam String filePath,
                                   @RequestParam(defaultValue = "10") int clients) {
        return csvScenarioService.runCsvScenarioConcurrent(filePath, clients);
    }

    @GetMapping("/log")
    public List<LogEntryResponse> printLog() {
        List<LogEntryResponse> replicaEntries = replicaLogRepository.findAll(Sort.by(Sort.Direction.ASC, "sequenceNumber"))
                .stream()
                .map(this::toLogEntryResponse)
                .toList();

        List<LogEntryResponse> readEntries = readLogRepository.findAll(Sort.by(Sort.Direction.ASC, "recordedAt"))
                .stream()
                .map(this::toReadLogEntryResponse)
                .toList();

        return Stream.concat(replicaEntries.stream(), readEntries.stream())
                .sorted(Comparator
                        .comparing((LogEntryResponse entry) ->
                                entry.lastUpdated() == null ? Instant.EPOCH : entry.lastUpdated())
                        .thenComparing(entry -> entry.sequenceNumber() == null ? "" : entry.sequenceNumber()))
                .toList();
    }

    @GetMapping(value = "/db", produces = {MediaType.APPLICATION_JSON_VALUE, MediaType.TEXT_PLAIN_VALUE})
    public ResponseEntity<?> printDb(@RequestParam(name = "format", defaultValue = "table") String format,
                                     @RequestParam(name = "scope", defaultValue = "cluster") String scope) {
        boolean clusterScope = !"local".equalsIgnoreCase(scope);
        List<NodeBalances> rows = clusterScope ? collectClusterBalances() : List.of(localNodeBalances());

        if ("json".equalsIgnoreCase(format)) {
            if (clusterScope) {
                List<NodeSnapshotResponse> payload = rows.stream()
                        .map(row -> new NodeSnapshotResponse(row.node(), row.accounts()))
                        .toList();
                return ResponseEntity.ok(payload);
            }
            return ResponseEntity.ok(rows.isEmpty() ? List.of() : rows.get(0).accounts());
        }

        String table = renderDbTable(rows);
        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_PLAIN)
                .body(table);
    }

    @GetMapping("/status/{sequence}")
    public StatusResponse printStatus(@PathVariable long sequence) {
        ReplicaLogEntity entry = replicaLogRepository.findById(sequence).orElse(null);
        if (entry == null) {
            return StatusResponse.fromState(sequence, nodeState);
        }
        return StatusResponse.from(entry);
    }

    @GetMapping("/views")
    public List<NewViewResponse> printViews(
            @RequestParam(name = "history", defaultValue = "false") boolean includeHistory) {
        List<NodeState.NewViewSnapshot> snapshots = nodeState.snapshotNewViewHistory(includeHistory);
        if (snapshots == null || snapshots.isEmpty()) {
            return List.of();
        }

        return snapshots.stream()
                .sorted(Comparator.comparingLong(snapshot -> snapshot.newView().getView()))
                .map(NewViewResponse::from)
                .toList();
    }

    private List<NodeBalances> collectClusterBalances() {
        List<NodeBalances> rows = new ArrayList<>();
        ClusterConfig config = nodeState.getClusterConfig();
        if (config == null || config.getNodes() == null || config.getNodes().isEmpty()) {
            rows.add(localNodeBalances());
            return rows;
        }

        for (ClusterConfig.NodeMetaData meta : config.getNodes()) {
            if (meta.getHttpPort() <= 0) continue;
            if (meta.getId() == nodeState.getNodeId()) {
                rows.add(localNodeBalances());
            } else {
                rows.add(new NodeBalances(nodeLabel(meta.getId()), fetchRemoteSnapshot(meta)));
            }
        }
        return rows;
    }

    private NodeBalances localNodeBalances() {
        return new NodeBalances(nodeLabel(nodeState.getNodeId()), loadLocalSnapshot());
    }

    private List<AccountSnapshot> loadLocalSnapshot() {
        return accountRepository.findAll(Sort.by(Sort.Direction.ASC, "name")).stream()
                .map(acc -> new AccountSnapshot(
                        acc.getName(),
                        acc.getBalance() == null ? 0L : acc.getBalance()))
                .toList();
    }

    private List<AccountSnapshot> fetchRemoteSnapshot(ClusterConfig.NodeMetaData meta) {
        String url = String.format("http://%s:%d/api/db?format=json&scope=local",
                meta.getHost(), meta.getHttpPort());
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(4))
                .GET()
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                List<AccountSnapshot> remote = objectMapper.readValue(response.body(), ACCOUNT_LIST_TYPE);
                return remote == null ? List.of() : remote;
            }
            log.warn("printDb: node-{} responded {} for {}", meta.getId(), response.statusCode(), url);
        } catch (Exception e) {
            log.warn("printDb: failed to contact node-{} ({}): {}", meta.getId(), url, e.getMessage());
        }
        return List.of();
    }

    private String renderDbTable(List<NodeBalances> rows) {
        LinkedHashSet<String> columns = new LinkedHashSet<>(DEFAULT_ACCOUNT_COLUMNS);
        rows.forEach(row -> row.accounts().forEach(acc -> columns.add(acc.name())));
        int labelWidth = Math.max(2, rows.stream()
                .map(NodeBalances::node)
                .mapToInt(String::length)
                .max()
                .orElse(2));

        Map<String, Integer> columnWidths = new LinkedHashMap<>();
        for (String col : columns) {
            int width = col.length();
            for (NodeBalances row : rows) {
                width = Math.max(width, String.valueOf(row.balance(col)).length());
            }
            columnWidths.put(col, width);
        }

        StringBuilder sb = new StringBuilder("printDB\n");
        appendRow(sb, "", columns, labelWidth, columnWidths, column -> column);
        for (NodeBalances row : rows) {
            appendRow(sb, row.node(), columns, labelWidth, columnWidths,
                    column -> String.valueOf(row.balance(column)));
        }
        return sb.toString();
    }

    private void appendRow(StringBuilder sb,
                           String label,
                           Iterable<String> columns,
                           int labelWidth,
                           Map<String, Integer> columnWidths,
                           java.util.function.Function<String, String> valueProvider) {
        sb.append("| ").append(pad(label, labelWidth)).append(" |");
        for (String column : columns) {
            String value = valueProvider.apply(column);
            sb.append(" ").append(pad(value, columnWidths.getOrDefault(column, value.length()))).append(" |");
        }
        sb.append('\n');
    }

    private String pad(String value, int width) {
        String v = value == null ? "" : value;
        if (v.length() >= width) {
            return v;
        }
        return v + " ".repeat(width - v.length());
    }

    private String nodeLabel(int nodeId) {
        return "n" + nodeId;
    }


    private record NodeBalances(String node,
                                List<AccountSnapshot> accounts,
                                Map<String, Long> index) {
        NodeBalances(String node, List<AccountSnapshot> accounts) {
            this(node,
                    accounts == null ? List.of() : accounts,
                    (accounts == null ? List.<AccountSnapshot>of() : accounts).stream()
                            .collect(Collectors.toMap(AccountSnapshot::name,
                                    AccountSnapshot::balance,
                                    (left, right) -> left,
                                    LinkedHashMap::new)));
        }

        long balance(String account) {
            return index.getOrDefault(account, 0L);
        }
    }

    private record NodeSnapshotResponse(String node, List<AccountSnapshot> accounts) {}

    private LogEntryResponse toLogEntryResponse(ReplicaLogEntity entity) {
        return new LogEntryResponse(
                formatSequence(entity.getSequenceNumber()),
                entity.getViewNumber(),
                entity.getPhase() == null ? "UNKNOWN" : entity.getPhase().name(),
                entity.isApproved(),
                entity.getDigest(),
                normalizePayload(entity.getPayload()),
                entity.getLastUpdated()
        );
    }

    private LogEntryResponse toReadLogEntryResponse(ReadLogEntity entity) {
        return new LogEntryResponse(
                "",
                0,
                "EXECUTED",
                true,
                "",
                normalizePayload(entity.getPayload()),
                entity.getRecordedAt()
        );
    }

    private String formatSequence(long seq) {
        if (seq >= BALANCE_SEQ_BASE) {
            return "";
        }
        return String.valueOf(seq);
    }

    private Object normalizePayload(String payload) {
        if (payload == null) return null;
        String trimmed = payload.trim();
        if (trimmed.isBlank()) return "";
        try {
            if ((trimmed.startsWith("{") && trimmed.endsWith("}"))
                    || (trimmed.startsWith("[") && trimmed.endsWith("]"))
                    || (trimmed.startsWith("\"") && trimmed.endsWith("\""))) {
                Object parsed = objectMapper.readValue(trimmed, Object.class);
                return sanitizePayload(parsed);
            }
        } catch (Exception ignored) { }
        return trimmed;
    }

    private Object sanitizePayload(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> copy = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String key = String.valueOf(entry.getKey());
                Object sanitized = sanitizePayload(entry.getValue());
                if ("clientId".equals(key) && sanitized instanceof String s) {
                    sanitized = friendlyClientId(s);
                }
                copy.put(key, sanitized);
            }
            return copy;
        }
        if (value instanceof List<?> list) {
            List<Object> copy = new ArrayList<>(list.size());
            for (Object item : list) {
                copy.add(sanitizePayload(item));
            }
            return copy;
        }
        return value;
    }

    private String friendlyClientId(String id) {
        Matcher matcher = CLIENT_ALIAS.matcher(id == null ? "" : id);
        if (matcher.matches()) {
            return "client" + matcher.group(1);
        }
        return id;
    }

    private record LogEntryResponse(String sequenceNumber,
                                    int viewNumber,
                                    String phase,
                                    boolean approved,
                                    String digest,
                                    Object payload,
                                    Instant lastUpdated) { }

    private record AccountSnapshot(String name, long balance) {}

    private record StatusResponse(long sequenceNumber,
                                  String statusLabel,
                                  String currentPhase,
                                  boolean prePrepared,
                                  boolean prepared,
                                  boolean committed,
                                  boolean executed,
                                  String digest,
                                  int viewNumber,
                                  Instant lastUpdated) {

        private static StatusResponse from(ReplicaLogEntity entity) {
            ReplicaLogEntity.Phase phase = entity.getPhase();
            boolean pp = phase != null;
            boolean p = atLeast(phase, ReplicaLogEntity.Phase.PREPARED);
            boolean c = atLeast(phase, ReplicaLogEntity.Phase.COMMITTED);
            boolean e = atLeast(phase, ReplicaLogEntity.Phase.EXECUTED);

            return new StatusResponse(
                    entity.getSequenceNumber(),
                    phaseToLabel(phase),
                    phase == null ? "UNKNOWN" : phase.name(),
                    pp, p, c, e,
                    entity.getDigest(),
                    entity.getViewNumber(),
                    entity.getLastUpdated()
            );
        }

        private static StatusResponse fromState(long seq, NodeState nodeState) {
            var preOpt = nodeState.getPrePrepareLog(seq);
            boolean prePrepared = preOpt.isPresent();
            boolean prepared = nodeState.preparesFor(seq).size() >= nodeState.quorumSize();
            boolean committed = nodeState.commitsFor(seq).size() >= nodeState.quorumSize();
            boolean executed = nodeState.getLastExecutedSequenceNumber() >= seq;

            String label;
            String phase;
            if (executed) {
                label = "E"; phase = "EXECUTED";
            } else if (committed) {
                label = "C"; phase = "COMMITTED";
            } else if (prepared) {
                label = "P"; phase = "PREPARED";
            } else if (prePrepared) {
                label = "PP"; phase = "PRE_PREPARE";
            } else {
                label = "X"; phase = "NO_STATUS";
            }

            String digest = preOpt.map(PrePrepare::getDigest).orElse(null);
            int view = preOpt.map(pp -> (int) pp.getView()).orElse(nodeState.getCurrentView());

            return new StatusResponse(
                    seq,
                    label,
                    phase,
                    prePrepared,
                    prepared,
                    committed,
                    executed,
                    digest,
                    view,
                    null
            );
        }

        private static boolean atLeast(ReplicaLogEntity.Phase current, ReplicaLogEntity.Phase target) {
            if (current == null || target == null) return false;
            return current.ordinal() >= target.ordinal();
        }

        private static String phaseToLabel(ReplicaLogEntity.Phase phase) {
            if (phase == null) return "X";
            return switch (phase) {
                case PRE_PREPARE -> "PP";
                case PREPARED -> "P";
                case COMMITTED -> "C";
                case EXECUTED -> "E";
            };
        }
    }

    private record NewViewResponse(long view,
                                   String newLeaderId,
                                   List<ViewChangeSummary> viewChanges,
                                   List<PrePrepareSummary> includedPrePrepares,
                                   CheckpointSnapshot checkpoint,
                                   String signatureBase64,
                                   Instant recordedAt,
                                   long generation) {

        private static NewViewResponse from(NodeState.NewViewSnapshot snapshot) {
            NewView newView = snapshot.newView();
            List<ViewChangeSummary> vcs = newView.getViewChangesList().stream()
                    .map(ViewChangeSummary::from)
                    .toList();

            List<PrePrepareSummary> pres = newView.getIncludedPrePreparesList().stream()
                    .sorted(Comparator.comparingLong(PrePrepare::getSequence))
                    .map(PrePrepareSummary::from)
                    .collect(Collectors.toList());

            return new NewViewResponse(
                    newView.getView(),
                    newView.getNewLeaderId(),
                    vcs,
                    pres,
                    newView.hasCheckpoint() ? CheckpointSnapshot.from(newView.getCheckpoint()) : null,
                    newView.getSignature(),
                    snapshot.recordedAt(),
                    snapshot.generation()
            );
        }
    }

    private record ViewChangeSummary(String replicaId,
                                     long newView,
                                     List<PreparedEntrySummary> preparedEntries,
                                     CheckpointSnapshot checkpoint,
                                     String signatureBase64) {

        private static ViewChangeSummary from(com.distributedsystems.pbft.proto.ViewChange vc) {
            List<PreparedEntrySummary> entries = vc.getPreparedMessagesList().stream()
                    .sorted(Comparator.comparingLong(PreparedEntry::getSequence))
                    .map(PreparedEntrySummary::from)
                    .toList();
            return new ViewChangeSummary(
                    vc.getReplicaId(),
                    vc.getNewView(),
                    entries,
                    vc.hasCheckpoint() ? CheckpointSnapshot.from(vc.getCheckpoint()) : null,
                    vc.getSignature());
        }
    }

    private record PreparedEntrySummary(long sequence,
                                        long view,
                                        String digest,
                                        String clientId) {
        private static PreparedEntrySummary from(PreparedEntry entry) {
            return new PreparedEntrySummary(
                    entry.getSequence(),
                    entry.getView(),
                    entry.getDigest(),
                    entry.getClientId()
            );
        }
    }

    private record PrePrepareSummary(long sequence,
                                     long view,
                                     String digest,
                                     String leaderId,
                                     String operation,
                                     String clientId) {

        private static PrePrepareSummary from(PrePrepare pre) {
            String op = pre.hasRequest() ? pre.getRequest().getOperation() : "";
            String client = pre.hasRequest() ? pre.getRequest().getClientId() : "";
            return new PrePrepareSummary(
                    pre.getSequence(),
                    pre.getView(),
                    pre.getDigest(),
                    pre.getLeaderId(),
                    op,
                    client
            );
        }
    }

    private record CheckpointSnapshot(long sequence, String label, String digest) {
        private static CheckpointSnapshot from(com.distributedsystems.pbft.proto.CheckpointSummary summary) {
            return new CheckpointSnapshot(
                    summary.getSequence(),
                    summary.getLabel(),
                    summary.getDigest()
            );
        }
    }



}
