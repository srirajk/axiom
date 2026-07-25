package com.openwolf.iam.dto;

import java.util.UUID;

public record RecoverySessionResponse(String accessToken, String tokenType, long expiresIn,
                                      UUID sessionId, String scope) {}
