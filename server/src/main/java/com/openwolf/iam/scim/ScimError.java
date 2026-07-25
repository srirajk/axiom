package com.openwolf.iam.scim;

import java.util.List;

public record ScimError(List<String> schemas, String detail, String status) {
    public static final String ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
    public ScimError(String detail, int status) { this(List.of(ERROR_SCHEMA), detail, Integer.toString(status)); }
}
