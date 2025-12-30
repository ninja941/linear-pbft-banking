package com.distributedsystems.pbft.repository;

import com.distributedsystems.pbft.model.DecrypterEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IDecrypterEntity extends JpaRepository<DecrypterEntity, String> {

}
