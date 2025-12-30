package com.distributedsystems.pbft.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Entity
@Table(name = "decrypter_entity")
@Data
public class DecrypterEntity {
    @Id
    @Column(name = "node_id", nullable = false, length = 64)
    private String nodeId;
    @Column(name = "public_key", columnDefinition = "TEXT", nullable = false)
    private String publicKey;

    @Column(name = "tss_public_share", columnDefinition = "TEXT")
    private String thresholdPublicShare;

    @Column(name = "tss_group_public", columnDefinition = "TEXT")
    private String thresholdGroupPublic;
}
