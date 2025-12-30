package com.distributedsystems.pbft.repository;

import com.distributedsystems.pbft.model.CheckpointEntity;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.Modifying;

import java.util.Optional;
import java.util.List;

public interface ICheckpointRepository extends JpaRepository<CheckpointEntity, Long> {
    Optional<CheckpointEntity> findTopByOrderBySequenceNumberDesc();
    boolean existsBySequenceNumber(long seq);
    Optional<CheckpointEntity> findBySequenceNumber(long sequenceNumber);
    List<CheckpointEntity> findAllByOrderBySequenceNumberDesc(Pageable pageable);

    @Modifying
    @Query("DELETE FROM CheckpointEntity c WHERE c.sequenceNumber < ?1")
    void deleteOlderThan(long sequenceToKeepInclusive);
}
