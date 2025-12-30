package com.distributedsystems.pbft.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Table(
        name = "replica_log",
        indexes = {
                @Index(name = "idx_replica_log_phase", columnList = "phase"),
                @Index(name = "idx_replica_log_approved", columnList = "approved"),
                @Index(name = "idx_replica_log_digest", columnList = "digest"),
                @Index(name = "idx_replica_log_pre_pre_digest", columnList = "prePrepareDigest")
        }
)
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ReplicaLogEntity {

    public enum Phase {
        PRE_PREPARE,
        PREPARED,
        COMMITTED,
        EXECUTED
    }

    @Id
    private long sequenceNumber;

    @Builder.Default
    private int viewNumber = 0;

    @Builder.Default
    private String digest = null;

    @Enumerated(EnumType.STRING)
    @Builder.Default
    private Phase phase = null;

    @Builder.Default
    private boolean approved = false;

    @Lob
    @Builder.Default
    private String payload = null;

    @Builder.Default
    private String prePrepareDigest = null;

    @Lob
    @Builder.Default
    private String prePreparePayload = null;

    @Builder.Default
    private String execResult = null;

    @Builder.Default
    private Instant lastUpdated = Instant.now();

    @Version
    @Builder.Default
    private long rowVersion = 0L;
}
