package com.openwolf.iam.policystudio;

public interface StudioGroundingProvider {

    StudioGroundingSnapshot snapshot(String tenantId, String resourceKind);
}
