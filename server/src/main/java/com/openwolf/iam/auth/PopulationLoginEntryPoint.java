package com.openwolf.iam.auth;

import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.service.TenantApplicationService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.io.IOException;
import java.util.function.Supplier;

/**
 * Sends an unauthenticated authorization request to the login page of the client's population: customer-facing
 * clients to the customer login, every other client (including the Axiom admin client) to the workforce login.
 */
public final class PopulationLoginEntryPoint implements AuthenticationEntryPoint {
    private final LoginUrlAuthenticationEntryPoint workforce = new LoginUrlAuthenticationEntryPoint("/login");
    private final LoginUrlAuthenticationEntryPoint customer = new LoginUrlAuthenticationEntryPoint(CustomerLoginFilter.LOGIN_PAGE);
    private final Supplier<TenantApplicationService> applications;

    public PopulationLoginEntryPoint(Supplier<TenantApplicationService> applications) {
        this.applications = applications;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException failure)
            throws IOException, ServletException {
        (customerClient(request) ? customer : workforce).commence(request, response, failure);
    }

    private boolean customerClient(HttpServletRequest request) {
        String clientId = request.getParameter("client_id");
        TenantApplicationService service = applications.get();
        return clientId != null && service != null && service.signInPopulation(clientId)
                .map(TenantApplicationClient.Population.CUSTOMER::equals).orElse(false);
    }
}
