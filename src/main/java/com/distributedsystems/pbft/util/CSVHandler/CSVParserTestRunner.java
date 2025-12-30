//package com.distributedsystems.pbft.util.CSVHandler;
//
//import com.distributedsystems.pbft.util.CSVHandler.CSVScenarioParser;
//import com.distributedsystems.pbft.state.NodeState;
//import org.springframework.boot.CommandLineRunner;
//import org.springframework.stereotype.Component;
//
//import java.io.InputStream;
//import java.util.List;
//
//@Component
//public class CSVParserTestRunner implements CommandLineRunner {
//
//    private final com.distributedsystems.pbft.util.CSVHandler.CSVScenarioParser parser;
//    private final NodeState nodeState;
//
//    public CSVParserTestRunner(CSVScenarioParser parser, NodeState nodeState) {
//        this.parser = parser;
//        this.nodeState = nodeState;
//    }
//
//    @Override
//    public void run(String... args) throws Exception {
//        System.out.println("\n=== Testing CSVScenarioParser ===");
//
//        try (InputStream in = getClass().getClassLoader().getResourceAsStream("transactions.csv")) {
//            if (in == null) {
//                System.err.println("❌ Could not find transactions.csv in resources/");
//                return;
//            }
//
//            List<CSVScenarioParser.ScenarioSet> sets = parser.parseScenarioFile(in);
//            System.out.println("✅ Parsed " + sets.size() + " sets");
//
//            for (var s : sets) {
//                System.out.println("\n--- SET " + s.getSetNumber() + " ---");
//                System.out.println("Transactions: " + s.getTransactions());
//                System.out.println("Live: " + s.getLiveNodes());
//                System.out.println("Byzantine: " + s.getByzantineNodes());
//                System.out.println("Attacks: " + s.getAttacks());
//                System.out.println("NodeState live: " + nodeState.getLiveNodes());
//                System.out.println("NodeState dead: " + nodeState.getDeadNodes());
//            }
//        }
//
//        System.out.println("\n=== CSV Scenario Parsing Complete ===");
//    }
//}
