package com.openwolf.iam.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.entity.CiamLifecycleEvent;
import com.openwolf.iam.repository.CiamLifecycleEventRepository;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.util.Map;
import java.util.List;
import com.openwolf.iam.dto.CiamContracts.CiamLifecycleEventResponse;

@Service
public class CiamLifecycleAuditService {
    private final CiamLifecycleEventRepository events;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    @org.springframework.beans.factory.annotation.Autowired
    public CiamLifecycleAuditService(CiamLifecycleEventRepository events, ObjectMapper objectMapper) {
        this(events, objectMapper, Clock.systemUTC());
    }

    CiamLifecycleAuditService(CiamLifecycleEventRepository events, ObjectMapper objectMapper, Clock clock) {
        this.events = events;
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    public void record(String tenantId, String actorId, String eventType,
                       String subjectType, String subjectId, Map<String, ?> details,
                       String correlationId) {
        try {
            events.save(new CiamLifecycleEvent(tenantId, actorId, eventType, subjectType,
                    subjectId, objectMapper.writeValueAsString(details), correlationId, clock.instant()));
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("CIAM lifecycle evidence could not be serialized", ex);
        }
    }

    public List<CiamLifecycleEventResponse> list(String tenantId) {
        return events.findByTenantIdOrderByOccurredAtAsc(tenantId).stream()
                .map(value -> new CiamLifecycleEventResponse(value.getId(), value.getActorId(),
                        value.getEventType(), value.getSubjectType(), value.getSubjectId(),
                        value.getDetails(), value.getCorrelationId(), value.getOccurredAt()))
                .toList();
    }
}
