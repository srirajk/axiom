package com.openwolf.iam.policystudio.lifecycle;

/** Fail-closed signal that another promotion attempt owns the full execution fence. */
public class PromotionExecutionBusyException extends RuntimeException {
    public PromotionExecutionBusyException(String message) { super(message); }
    public PromotionExecutionBusyException(String message, Throwable cause) { super(message, cause); }
}
