package com.openwolf.iam.dto;

public record IdentityControlApplyResponse(IdentityControlRequestResponse request, String resultReference,
                                           String oneTimeSecret) {
    @Override
    public String toString() {
        return "IdentityControlApplyResponse[request=" + request + ", resultReference=" + resultReference
                + ", oneTimeSecret=" + (oneTimeSecret == null ? "absent" : "[REDACTED]") + "]";
    }
}
