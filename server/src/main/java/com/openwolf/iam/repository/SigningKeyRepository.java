package com.openwolf.iam.repository;

import com.openwolf.iam.entity.SigningKey;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SigningKeyRepository extends JpaRepository<SigningKey, UUID> {
    List<SigningKey> findByDeploymentId(String deploymentId);
    Optional<SigningKey> findByDeploymentIdAndState(String deploymentId, SigningKey.State state);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select k from SigningKey k where k.deploymentId = :deploymentId and k.state = :state")
    Optional<SigningKey> findByDeploymentIdAndStateForUpdate(String deploymentId, SigningKey.State state);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select k from SigningKey k where k.id = :id")
    Optional<SigningKey> findByIdForUpdate(UUID id);
}
