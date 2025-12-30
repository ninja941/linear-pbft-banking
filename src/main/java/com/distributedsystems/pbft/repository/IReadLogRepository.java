package com.distributedsystems.pbft.repository;

import com.distributedsystems.pbft.model.ReadLogEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface IReadLogRepository extends JpaRepository<ReadLogEntity, Long> {
}
