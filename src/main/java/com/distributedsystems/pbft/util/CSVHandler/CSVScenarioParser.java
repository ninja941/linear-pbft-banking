package com.distributedsystems.pbft.util.CSVHandler;

import com.distributedsystems.pbft.state.NodeState;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.*;

@Component
public class CSVScenarioParser {

    private final NodeState nodeState;

    public CSVScenarioParser(NodeState nodeState) {
        this.nodeState = nodeState;
    }

    public static class ScenarioSet {
        private int setNumber;
        private final List<String> transactions = new ArrayList<>();
        private List<String> liveNodes = new ArrayList<>();
        private List<String> byzantineNodes = new ArrayList<>();
        private List<String> attacks = new ArrayList<>();

        public int getSetNumber() { return setNumber; }
        public List<String> getTransactions() { return transactions; }
        public List<String> getLiveNodes() { return liveNodes; }


        public void setSetNumber(int setNumber) { this.setNumber = setNumber; }
        public void setLiveNodes(List<String> liveNodes) { this.liveNodes = liveNodes; }
        public void setByzantineNodes(List<String> byzantineNodes) { this.byzantineNodes = byzantineNodes; }
        public void setAttacks(List<String> attacks) { this.attacks = attacks; }
    }

    public List<ScenarioSet> parseScenarioFile(InputStream inputStream) throws Exception {
        List<ScenarioSet> result = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            CSVParser parser = new CSVParser(reader, CSVFormat.DEFAULT
                    .withIgnoreEmptyLines()
                    .withTrim()
                    .withAllowMissingColumnNames()
                    .withFirstRecordAsHeader());

            Map<Integer, ScenarioSet> map = new LinkedHashMap<>();
            int lastSetNumber = -1;

            for (CSVRecord record : parser) {
                String setNumRaw = record.get("Set Number").trim();
                if (setNumRaw.isEmpty() && lastSetNumber == -1) continue; // skip invalid first rows

                int setNum = setNumRaw.isEmpty() ? lastSetNumber : Integer.parseInt(setNumRaw);
                lastSetNumber = setNum;

                ScenarioSet set = map.computeIfAbsent(setNum, k -> {
                    ScenarioSet s = new ScenarioSet();
                    s.setSetNumber(setNum);
                    return s;
                });

                String txn = record.get("Transactions").trim();
                if (!txn.isEmpty()) set.getTransactions().add(txn);

                if (record.isMapped("Live")) {
                    String live = record.get("Live").trim();
                    if (!live.isEmpty()) {
                        List<String> liveList = parseBracketList(live);
                        set.setLiveNodes(liveList);
                    }
                }

                if (record.isMapped("Byzantine")) {
                    String byz = record.get("Byzantine").trim();
                    if (!byz.isEmpty()) set.setByzantineNodes(parseBracketList(byz));
                }

                if (record.isMapped("Attack")) {
                    String atk = record.get("Attack").trim();
                    if (!atk.isEmpty()) set.setAttacks(parseBracketList(atk));
                }
            }

            result.addAll(map.values());
        }
        return result;
    }

    private List<String> parseBracketList(String str) {
        str = str.replace("[", "").replace("]", "").trim();
        if (str.isEmpty()) return Collections.emptyList();
        String[] parts = str.split("[,;]");
        List<String> list = new ArrayList<>();
        for (String p : parts) {
            if (!p.trim().isEmpty()) list.add(p.trim());
        }
        return list;
    }

}
