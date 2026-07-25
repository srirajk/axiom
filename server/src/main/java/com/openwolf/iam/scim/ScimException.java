package com.openwolf.iam.scim;

public class ScimException extends RuntimeException {
    private final int status;
    public ScimException(int status, String detail) { super(detail); this.status = status; }
    public int status() { return status; }
}
