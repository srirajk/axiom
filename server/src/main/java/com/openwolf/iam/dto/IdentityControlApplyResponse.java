package com.openwolf.iam.dto;

public record IdentityControlApplyResponse(IdentityControlRequestResponse request, String resultReference,
                                           String oneTimeSecret) {}
