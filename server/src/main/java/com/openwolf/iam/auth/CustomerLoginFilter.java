package com.openwolf.iam.auth;

import com.openwolf.iam.service.CiamCustomerAuthenticationService;
import com.openwolf.iam.service.TenantApplicationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Processes Axiom's customer (CIAM) login form ({@code POST /login/customer}, CSRF-protected by the chain). The tenant is
 * never taken from the form: it is the tenant of the customer-facing client named by the saved authorization request,
 * so a customer can sign in only as part of an authorization request of a customer-population client. Credentials are
 * checked by the same service as every other customer sign-in (ACTIVE, verified customers only). On success the
 * session id changes (fixation defence) and the browser resumes the saved authorization request.
 */
public final class CustomerLoginFilter extends AbstractAuthenticationProcessingFilter {
    public static final String LOGIN_PAGE = "/login/customer";

    private final Supplier<CiamCustomerAuthenticationService> customers;
    private final Supplier<TenantApplicationService> applications;
    private final RequestCache requestCache = new HttpSessionRequestCache();

    public CustomerLoginFilter(Supplier<CiamCustomerAuthenticationService> customers,
                               Supplier<TenantApplicationService> applications) {
        super(new AntPathRequestMatcher(LOGIN_PAGE, "POST"));
        this.customers = customers;
        this.applications = applications;
        setAuthenticationManager(authentication -> {
            throw new IllegalStateException("customer login authenticates directly");
        });
        setSessionAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
        setSecurityContextRepository(new HttpSessionSecurityContextRepository());
        SavedRequestAwareAuthenticationSuccessHandler success = new SavedRequestAwareAuthenticationSuccessHandler();
        success.setRequestCache(requestCache);
        setAuthenticationSuccessHandler(success);
        setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler(LOGIN_PAGE + "?error"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        SavedRequest saved = requestCache.getRequest(request, response);
        String[] clientIds = saved == null ? null : saved.getParameterValues("client_id");
        if (clientIds == null || clientIds.length != 1) {
            throw new BadCredentialsException("customer sign-in requires a pending authorization request");
        }
        TenantApplicationService applicationService = applications.get();
        CiamCustomerAuthenticationService customerService = customers.get();
        if (applicationService == null || customerService == null) {
            throw new BadCredentialsException("customer sign-in is unavailable");
        }
        TenantApplicationService.ClientAuthority client = applicationService.activeAuthority(clientIds[0])
                .filter(TenantApplicationService.ClientAuthority::customerSignIn)
                .orElseThrow(() -> new BadCredentialsException("customer sign-in requires a customer-facing client"));
        String email = request.getParameter("username");
        String password = request.getParameter("password");
        if (email == null || email.isBlank() || password == null || password.isEmpty()) {
            throw new BadCredentialsException("customer authentication failed");
        }
        CiamCustomerAuthenticationService.AuthenticatedCustomer customer;
        try {
            customer = customerService.authenticate(client.tenantId(), email, password);
        } catch (RuntimeException failed) {
            throw new BadCredentialsException("customer authentication failed");
        }
        UUID id = customer.customerId();
        return new CustomerAuthenticationToken(id.toString(), client.tenantId(), customer.tokenVersion(),
                new AssuranceAuthenticationDetails(request, Instant.now(), AuthenticationAssurance.PASSWORD));
    }
}
