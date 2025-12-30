package com.distributedsystems.pbft.repository;

import com.distributedsystems.pbft.model.ClientAccountEntity;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
@Repository
public interface IClientAccountRepository extends JpaRepository<ClientAccountEntity,Long> {
    Optional<ClientAccountEntity> findByName(String name);
    @Modifying
    @Transactional
    @Query("UPDATE ClientAccountEntity a SET a.balance = :balance WHERE a.name = :name")
    void updateBalance(@Param("name") String name, @Param("balance") Long balance);

    @Modifying
    @Transactional
    @Query(value = "UPDATE client_account SET balance = :balance", nativeQuery = true)
    int resetAllBalances(@Param("balance") Long balance);
}
