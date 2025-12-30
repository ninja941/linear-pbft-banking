package com.distributedsystems.pbft.util.CSVHandler;

import com.distributedsystems.pbft.client.ReplicaClient;
import com.distributedsystems.pbft.model.ReadLogEntity;
import com.distributedsystems.pbft.proto.ClientReply;
import com.distributedsystems.pbft.repository.IClientAccountRepository;
import com.distributedsystems.pbft.repository.IReadLogRepository;
import com.distributedsystems.pbft.service.PbftServiceImpl;
import com.distributedsystems.pbft.state.NodeState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;


@Slf4j
@Service
public class CSVScenarioRunner {

    private final CSVScenarioParser parser;
    private final NodeState nodeState;
    private final IClientAccountRepository accountRepo;
    private final IReadLogRepository readLogRepository;
    private final PbftServiceImpl pbftService;
    private final ReplicaClient replicaClient;

    public CSVScenarioRunner(
            CSVScenarioParser parser,
            NodeState nodeState,
            IClientAccountRepository accountRepo,
            IReadLogRepository readLogRepository,
            PbftServiceImpl pbftService,
            ReplicaClient replicaClient) {
        this.parser = parser;
        this.nodeState = nodeState;
        this.accountRepo = accountRepo;
        this.readLogRepository = readLogRepository;
        this.pbftService = pbftService;
        this.replicaClient = replicaClient;
    }

    private InputStream resolveCsv(String filename) throws Exception {
        ClassPathResource resource = new ClassPathResource(filename);
        if (resource.exists()) {
            log.info("Found CSV in classpath: {}", resource.getPath());
            return resource.getInputStream();
        }

        File devFile = new File("src/main/resources/" + filename);
        if (devFile.exists()) {
            log.info("Found CSV in src/main/resources: {}", devFile.getAbsolutePath());
            return new FileInputStream(devFile);
        }

        File targetFile = new File("target/classes/" + filename);
        if (targetFile.exists()) {
            log.info("Found CSV in target/classes: {}", targetFile.getAbsolutePath());
            return new FileInputStream(targetFile);
        }

        throw new IllegalArgumentException("File not found: " + filename);
    }

    public void runScenario(String csvFile) throws Exception {
        try (InputStream in = resolveCsv(csvFile)) {
            List<CSVScenarioParser.ScenarioSet> sets = parser.parseScenarioFile(in);

            for (CSVScenarioParser.ScenarioSet set : sets) {
                log.info("\n==============================");
                log.info(">>> EXECUTING SET {}", set.getSetNumber());
                log.info("==============================");

                applyLiveRoster(set.getLiveNodes());

                for (String txn : set.getTransactions()) {
                    if (txn == null || txn.isBlank()) continue;

                    String clean = txn.replace("\"", "").trim();

                    // 💰 Case 1: Balance query e.g. (G)
                    if (clean.matches("\\(\\s*[A-Z]\\s*\\)")) {
                        String client = clean.replace("(", "")
                                .replace(")", "")
                                .trim();

                        var acc = accountRepo.findByName(client)
                                .orElseThrow(() -> new IllegalStateException("No such client: " + client));

                        long balance = acc.getBalance();
                        log.info("[{}] Balance({}) = {}", nodeState.getSelfNodeId(), client, balance);
                        recordBalanceRead(set.getSetNumber(), client, balance);
                        continue;
                    }

                    String[] parts = clean.replace("(", "")
                            .replace(")", "")
                            .split(",");
                    if (parts.length == 3) {
                        String from = parts[0].trim();
                        String to = parts[1].trim();
                        long amt = Long.parseLong(parts[2].trim());
                        // Use stable timestamp across retries so duplicates are detected as same request
                        long ts = System.currentTimeMillis();
                        String clientId = "csv-" + set.getSetNumber() + "-" + from;

                        log.info("[{}] CSV TXN: {} → {} : {} (client={}, ts={})",
                                nodeState.getSelfNodeId(), from, to, amt, clientId, ts);

                        // Submit with a repeating timer until final SUCCESS
                        replicaClient.submitUntilExecuted(
                                from, to, amt, clientId, ts,
                                java.time.Duration.ofSeconds(8),   // per-attempt RPC timeout
                                java.time.Duration.ofSeconds(6));  // retry every 6s until SUCCESS
                    } else {
                        log.warn("[{}] ⚠️ Ignored malformed txn: {}", nodeState.getSelfNodeId(), clean);
                    }
                }
            }
        }
    }

    private void applyLiveRoster(List<String> liveNodes) {
        if (liveNodes == null || liveNodes.isEmpty()) {
            log.info("[{}] Live column empty → keeping existing roster.", nodeState.getSelfNodeId());
            return;
        }

        Set<Integer> lives = new LinkedHashSet<>();
        for (String raw : liveNodes) {
            if (raw == null) continue;
            String cleaned = raw.trim();
            if (cleaned.isEmpty()) continue;
            if (cleaned.startsWith("n") || cleaned.startsWith("N")) {
                cleaned = cleaned.substring(1);
            }
            try {
                lives.add(Integer.parseInt(cleaned));
            } catch (NumberFormatException e) {
                log.warn("[{}] Skipping invalid live node token '{}'", nodeState.getSelfNodeId(), raw);
            }
        }

        nodeState.replaceLiveSet(lives);
        log.info("[{}] Applied live roster for set → {}", nodeState.getSelfNodeId(), lives);
    }

    private static class NoOpReplyObserver implements io.grpc.stub.StreamObserver<ClientReply> {
        @Override public void onNext(ClientReply value) {}
        @Override public void onError(Throwable t) { log.error("Client request failed: {}", t.getMessage()); }
        @Override public void onCompleted() {}
    }

    private void recordBalanceRead(int setNumber, String account, long balance) {
        if (readLogRepository == null) return;
        try {
            String payload = String.format(
                    "{\"set\":\"%s\",\"operation\":\"BALANCE\",\"account\":\"%s\",\"response\":\"%s\"}",
                    setNumber,
                    account == null ? "" : account,
                    "BALANCE=" + balance);
            ReadLogEntity entry = ReadLogEntity.builder()
                    .source(String.valueOf(setNumber))
                    .account(account == null ? "" : account)
                    .payload(payload)
                    .result("BALANCE=" + balance)
                    .recordedAt(Instant.now())
                    .build();
            readLogRepository.save(entry);
        } catch (Exception e) {
            log.warn("[{}] Failed to record BALANCE({}) read: {}", nodeState.getSelfNodeId(), account, e.getMessage());
        }
    }
}
