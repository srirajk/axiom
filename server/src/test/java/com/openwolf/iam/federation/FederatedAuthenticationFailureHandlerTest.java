package com.openwolf.iam.federation;

import com.openwolf.iam.repository.IdentitySourceRepository;
import com.openwolf.iam.service.AuditService;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.AuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class FederatedAuthenticationFailureHandlerTest {
    @Test
    void auditFailureStillUsesTheSameGenericRedirect() throws Exception {
        AuditService audit = mock(AuditService.class);
        doThrow(new IllegalStateException("database details")).when(audit).log(
                any(), any(), any(), any(), any(), any(), any(), any());
        FederatedAuthenticationFailureHandler handler =
                new FederatedAuthenticationFailureHandler(audit, mock(IdentitySourceRepository.class));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login/oauth2/code/source");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(request, response, mock(AuthenticationException.class));

        assertThat(response.getRedirectedUrl()).isEqualTo("/login?error=federated");
        verify(audit).log(any(), any(), any(), any(), any(), any(), any(), any());
    }
}
