package com.openwolf.iam.dto;

import com.openwolf.iam.entity.ExternalIdentityLink;
import java.time.Instant;
import java.util.UUID;

public record ExternalIdentityLinkResponse(
        UUID id, UUID sourceId, String issuer, String subject, String principalId,
        ExternalIdentityLink.Status status, Instant createdAt, Instant updatedAt) {}
