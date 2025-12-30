package com.distributedsystems.pbft.repository;

import com.distributedsystems.pbft.model.ClientPrivateKeyEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IClientPrivateKeyRepository extends JpaRepository<ClientPrivateKeyEntity, String> {
}
