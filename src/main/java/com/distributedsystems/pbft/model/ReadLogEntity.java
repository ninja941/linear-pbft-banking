package com.distributedsystems.pbft.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Table(name = "read_log")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ReadLogEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String source;

    private String account;

    @Lob
    private String payload;

    private String result;

    @Builder.Default
    private Instant recordedAt = Instant.now();
}
