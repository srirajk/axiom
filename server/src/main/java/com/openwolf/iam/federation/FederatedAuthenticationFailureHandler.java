package com.openwolf.iam.federation;

import com.openwolf.iam.service.AuditService;
import com.openwolf.iam.repository.IdentitySourceRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/** Uniform browser failure response with a detailed server-side audit event. */
@Component
public final class FederatedAuthenticationFailureHandler implements AuthenticationFailureHandler {
    private final AuditService audit;
    private final IdentitySourceRepository sources;
    private final SimpleUrlAuthenticationFailureHandler redirect =
            new SimpleUrlAuthenticationFailureHandler("/login?error=federated");

    public FederatedAuthenticationFailureHandler(AuditService audit, IdentitySourceRepository sources) {
        this.audit = audit; this.sources = sources;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        try {
            audit.log(sourceTenant(request), "system", "FEDERATED_LOGIN_DENIED", "identity_source",
                    request.getRequestURI(), null, exception.getClass().getSimpleName(), request);
        } catch (RuntimeException ignored) {
            // Audit failure must not change the generic browser response or expose its details.
        }
        redirect.onAuthenticationFailure(request, response, exception);
    }

    private String sourceTenant(HttpServletRequest request) {
        String[] parts = request.getRequestURI().split("/");
        if (parts.length > 0) {
            String registration = parts[parts.length - 1];
            try {
                var key = IdentitySourceClientRegistrationRepository.RegistrationKey.parse(registration);
                return sources.findById(key.sourceId()).map(value -> value.getTenantId()).orElse("federated-login");
            } catch (IllegalArgumentException ignored) {
                // Keep the externally identical response even when the source cannot be recovered.
            }
        }
        return "federated-login";
    }
}
