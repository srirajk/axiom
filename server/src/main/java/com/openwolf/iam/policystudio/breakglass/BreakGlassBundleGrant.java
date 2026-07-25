package com.openwolf.iam.policystudio.breakglass;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Immutable membership edge proving which break-glass grants are carried by a promoted bundle. */
@Entity
@Table(name = "break_glass_bundle_grants")
public class BreakGlassBundleGrant {
    @Id private String id;
    @Column(name = "bundle_id", nullable = false) private String bundleId;
    @Column(name = "grant_id", nullable = false) private String grantId;

    protected BreakGlassBundleGrant() {}
    public BreakGlassBundleGrant(String bundleId, String grantId) {
        this.id = bundleId + ":" + grantId;
        this.bundleId = bundleId;
        this.grantId = grantId;
    }
    public String getBundleId() { return bundleId; }
    public String getGrantId() { return grantId; }
}
