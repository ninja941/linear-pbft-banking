package com.distributedsystems.pbft.repository;

import com.distributedsystems.pbft.model.EncrypterEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface IEncrypterEntity extends JpaRepository<EncrypterEntity, String> {
}
