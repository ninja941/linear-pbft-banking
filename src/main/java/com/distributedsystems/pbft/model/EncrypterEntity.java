package com.distributedsystems.pbft.model;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "encrypter_entity")
@Data
public class EncrypterEntity {

    @Id
    @Column(name = "node_id", nullable = false, length = 64)
    private String nodeId;

    @Column(name = "private_key", columnDefinition = "TEXT", nullable = false)
    private String privateKey;

    @Column(name = "tss_private_share", columnDefinition = "TEXT")
    private String thresholdPrivateShare;

}
