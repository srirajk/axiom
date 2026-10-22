package com.openwolf.iam.dto;

/** Minimal, tenant-bound person profile returned to an authorized service client. */
public record UserProfileResponse(String subject, String name, String given_name,
                                  String family_name, String email) {}
