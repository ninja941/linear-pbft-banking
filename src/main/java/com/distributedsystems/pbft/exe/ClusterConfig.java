package com.distributedsystems.pbft.exe;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "pbft.cluster")
@Data
public class ClusterConfig {
    private int totalNodes;
    private int byzantineNodes;
    private int checkpointInterval;
    private List<NodeMetaData> nodes;


    @Data
    public static class NodeMetaData {
        private int id;
        private String host;
        private int grpcPort;
        private int httpPort;
    }
}
