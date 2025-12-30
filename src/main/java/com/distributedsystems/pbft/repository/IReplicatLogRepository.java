package com.distributedsystems.pbft.repository;

import com.distributedsystems.pbft.model.ReplicaLogEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
@Repository
public interface IReplicatLogRepository extends JpaRepository<ReplicaLogEntity, Long> {
    List<ReplicaLogEntity> findByDigest(String digest);
    ReplicaLogEntity findTopByDigestOrderByLastUpdatedDesc(String digest);
}
