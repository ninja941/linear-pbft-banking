package com.distributedsystems.pbft.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "client_private_keys")
public class ClientPrivateKeyEntity {

    @Id
    @Column(name = "client_id", nullable = false, length = 128)
    private String clientId;

    @Column(name = "private_key", columnDefinition = "TEXT", nullable = false)
    private String privateKey;
}
