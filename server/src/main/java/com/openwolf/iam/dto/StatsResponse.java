package com.openwolf.iam.dto;

public record StatsResponse(
        long totalUsers,
        long totalRoles,
        long totalTeams
) {}
