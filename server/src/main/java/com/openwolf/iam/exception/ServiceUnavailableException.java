package com.openwolf.iam.exception;

/** A capability depends on a provider or trust anchor that is absent or unreachable; the request is refused. */
public class ServiceUnavailableException extends RuntimeException {
    public ServiceUnavailableException(String message) {
        super(message);
    }
}
