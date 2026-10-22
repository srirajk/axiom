package com.openwolf.iam.service;

import com.openwolf.iam.auth.BusinessScopeRegistry;
import com.openwolf.iam.dto.AgentExchangeContracts.BrokerTargetResponse;
import com.openwolf.iam.dto.AgentExchangeContracts.CreateBrokerTargetRequest;
import com.openwolf.iam.entity.AgentExchangeRoute;
import com.openwolf.iam.entity.AgentWorkloadIdentity;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.entity.TrustedExchangeBroker;
import com.openwolf.iam.entity.TrustedExchangeBrokerTarget;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.AgentWorkloadIdentityRepository;
import com.openwolf.iam.repository.TrustedExchangeBrokerRepository;
import com.openwolf.iam.repository.TrustedExchangeBrokerTargetRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/** Broker-owned target authority; consumer-specific authorization remains outside Axiom. */
@Service
@Transactional
public class TrustedBrokerTargetService {
    private static final OAuth2Error INVALID_TARGET = new OAuth2Error("invalid_target");

    private final TrustedExchangeBrokerTargetRepository targets;
    private final TrustedExchangeBrokerRepository brokers;
    private final AgentWorkloadIdentityRepository workloads;
    private final TenantApplicationService applications;
    private final CiamLifecycleAuditService audit;
    private final BusinessScopeRegistry businessScopes;
    private final Clock clock;

    @org.springframework.beans.factory.annotation.Autowired
    public TrustedBrokerTargetService(TrustedExchangeBrokerTargetRepository targets,
                                      TrustedExchangeBrokerRepository brokers,
                                      AgentWorkloadIdentityRepository workloads,
                                      TenantApplicationService applications,
                                      CiamLifecycleAuditService audit,
                                      BusinessScopeRegistry businessScopes) {
        this(targets, brokers, workloads, applications, audit, businessScopes, Clock.systemUTC());
    }

    TrustedBrokerTargetService(TrustedExchangeBrokerTargetRepository targets,
                               TrustedExchangeBrokerRepository brokers,
                               AgentWorkloadIdentityRepository workloads,
                               TenantApplicationService applications,
                               CiamLifecycleAuditService audit,
                               BusinessScopeRegistry businessScopes, Clock clock) {
        this.targets = targets;
        this.brokers = brokers;
        this.workloads = workloads;
        this.applications = applications;
        this.audit = audit;
        this.businessScopes = businessScopes;
        this.clock = clock;
    }

    public BrokerTargetResponse create(String tenantId, UUID brokerId, CreateBrokerTargetRequest request,
                                       String actorId, String correlationId) {
        TrustedExchangeBroker broker = activeBroker(tenantId, brokerId);
        String audience = request.audience().trim();
        if (audience.equals(broker.getGatewayAudience()) || !applications.isActiveAudience(tenantId, audience)) {
            throw new IllegalArgumentException("target must be an active tenant application audience, not the Gateway");
        }
        TreeSet<String> scopes = new TreeSet<>();
        for (String raw : request.scopes()) {
            String scope = raw.trim();
            if (scope.isBlank() || !businessScopes.isApproved(tenantId, scope)) {
                throw new IllegalArgumentException("target scopes must be approved tenant business scopes");
            }
            scopes.add(scope);
        }
        applications.activeAuthority(broker.getOauthClientId())
                .filter(value -> value.tenantId().equals(tenantId))
                .filter(value -> value.clientType() == TenantApplicationClient.Type.CONFIDENTIAL_SERVICE)
                .orElseThrow(() -> new IllegalArgumentException("broker OAuth client is inactive"));
        if (request.destinationType() == AgentExchangeRoute.DestinationType.AGENT) {
            if (request.destinationWorkloadId() == null) {
                throw new IllegalArgumentException("workload target requires destinationWorkloadId");
            }
            AgentWorkloadIdentity destination = workloads.findByTenantIdAndId(tenantId, request.destinationWorkloadId())
                    .filter(value -> value.getStatus() == AgentWorkloadIdentity.Status.ACTIVE)
                    .orElseThrow(() -> new IllegalArgumentException("target workload is inactive or unknown"));
            var destinationClient = applications.activeAuthority(destination.getOauthClientId())
                    .filter(value -> value.tenantId().equals(tenantId))
                    .filter(value -> value.clientType() == TenantApplicationClient.Type.CONFIDENTIAL_SERVICE)
                    .orElseThrow(() -> new IllegalArgumentException("target workload client is inactive"));
            if (!destinationClient.audience().equals(audience) || !destinationClient.scopes().containsAll(scopes)) {
                throw new IllegalArgumentException("target exceeds destination workload authority");
            }
        } else if (request.destinationType() != AgentExchangeRoute.DestinationType.RESOURCE
                || request.destinationWorkloadId() != null) {
            throw new IllegalArgumentException("resource target cannot name a workload; Gateway is not a target");
        }
        if (targets.findByTenantIdAndBrokerIdAndAudienceOrderByCreatedAtDesc(tenantId, brokerId, audience)
                .stream().anyMatch(value -> value.getStatus() == TrustedExchangeBrokerTarget.Status.ACTIVE)) {
            throw new ResourceConflictException("active broker target already exists");
        }
        TrustedExchangeBrokerTarget target = targets.save(new TrustedExchangeBrokerTarget(brokerId, tenantId,
                audience, request.destinationType(), request.destinationWorkloadId(), scopes.stream().toList(),
                request.purpose().trim(), clock.instant()));
        audit.record(tenantId, actorId, "TRUSTED_EXCHANGE_BROKER_TARGET_CREATED", "trusted_exchange_broker_target",
                target.getId().toString(), Map.of("brokerId", brokerId, "audience", audience,
                        "destinationType", target.getDestinationType(), "scopes", scopes), correlationId);
        return response(target);
    }

    @Transactional(readOnly = true)
    public List<BrokerTargetResponse> list(String tenantId, UUID brokerId) {
        broker(tenantId, brokerId);
        return targets.findByTenantIdAndBrokerIdOrderByCreatedAtAsc(tenantId, brokerId)
                .stream().map(TrustedBrokerTargetService::response).toList();
    }

    public BrokerTargetResponse revoke(String tenantId, UUID brokerId, UUID targetId,
                                       String actorId, String correlationId) {
        broker(tenantId, brokerId);
        TrustedExchangeBrokerTarget target = targets.findByTenantIdAndBrokerIdAndId(tenantId, brokerId, targetId)
                .orElseThrow(() -> EntityNotFoundException.forId("Broker target", targetId));
        boolean changed = target.getStatus() == TrustedExchangeBrokerTarget.Status.ACTIVE;
        target.revoke(clock.instant());
        if (changed) audit.record(tenantId, actorId, "TRUSTED_EXCHANGE_BROKER_TARGET_REVOKED",
                "trusted_exchange_broker_target", targetId.toString(),
                Map.of("brokerId", brokerId, "audience", target.getAudience()), correlationId);
        return response(target);
    }

    /** Empty means no broker-target policy exists and the legacy route may be consulted. */
    @Transactional(readOnly = true)
    public Optional<TrustedExchangeBrokerTarget> resolve(String tenantId, UUID brokerId, String audience) {
        List<TrustedExchangeBrokerTarget> entries = targets
                .findByTenantIdAndBrokerIdAndAudienceOrderByCreatedAtDesc(tenantId, brokerId, audience);
        if (entries.isEmpty()) return Optional.empty();
        return Optional.of(entries.stream()
                .filter(value -> value.getStatus() == TrustedExchangeBrokerTarget.Status.ACTIVE)
                .findFirst().orElseThrow(() -> new OAuth2AuthenticationException(INVALID_TARGET)));
    }

    @Transactional(readOnly = true)
    public TrustedExchangeBrokerTarget requireActive(String tenantId, UUID brokerId, UUID targetId) {
        return targets.findByTenantIdAndBrokerIdAndId(tenantId, brokerId, targetId)
                .filter(value -> value.getStatus() == TrustedExchangeBrokerTarget.Status.ACTIVE)
                .orElseThrow(() -> new OAuth2AuthenticationException(new OAuth2Error("invalid_grant")));
    }

    private TrustedExchangeBroker activeBroker(String tenantId, UUID brokerId) {
        TrustedExchangeBroker broker = broker(tenantId, brokerId);
        if (broker.getStatus() != TrustedExchangeBroker.Status.ACTIVE) {
            throw new IllegalArgumentException("trusted broker is revoked");
        }
        return broker;
    }

    private TrustedExchangeBroker broker(String tenantId, UUID brokerId) {
        return brokers.findById(brokerId).filter(value -> value.getTenantId().equals(tenantId))
                .orElseThrow(() -> EntityNotFoundException.forId("Trusted exchange broker", brokerId));
    }

    private static BrokerTargetResponse response(TrustedExchangeBrokerTarget value) {
        return new BrokerTargetResponse(value.getId(), value.getBrokerId(), value.getAudience(),
                value.getDestinationType(), value.getDestinationWorkloadId(), value.getAllowedScopes(),
                value.getPurpose(), value.getStatus(), value.getCreatedAt(), value.getRevokedAt(),
                value.getRevision());
    }
}
