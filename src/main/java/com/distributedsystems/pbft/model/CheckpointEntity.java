package com.distributedsystems.pbft.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Table(name = "checkpoint")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CheckpointEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private long sequenceNumber;

    @Column(nullable = false, length = 128)
    private String label;

    @Column(nullable = false, length = 128)
    private String digest;

    @Column(name = "certificate_digest", length = 88)
    private String certificateDigest;

    @Lob
    @Column(name = "serialized_state", columnDefinition = "TEXT")
    private String serializedState;

    @Column(name = "certificate_json", columnDefinition = "TEXT")
    private String certificateJson;

    @Column(name = "proof_count")
    private int proofCount;

    @Builder.Default
    @Column(nullable = false)
    private Instant createdAt = Instant.now();
}
