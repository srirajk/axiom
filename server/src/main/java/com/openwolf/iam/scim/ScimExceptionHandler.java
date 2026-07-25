package com.openwolf.iam.scim;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;

@RestControllerAdvice(basePackageClasses = com.openwolf.iam.controller.ScimController.class)
@Order(Ordered.HIGHEST_PRECEDENCE)
public class ScimExceptionHandler {
    @ExceptionHandler(ScimException.class)
    public ResponseEntity<ScimError> handle(ScimException exception) {
        return ResponseEntity.status(exception.status()).contentType(MediaType.parseMediaType("application/scim+json"))
                .body(new ScimError(exception.getMessage(), exception.status()));
    }
}
