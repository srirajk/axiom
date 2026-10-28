package com.openwolf.iam.auth;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.server.authorization.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class FreshCimdConsentServiceTest {
    @Test void rememberedConsentCannotAuthorizeAFreshCimdDecisionButRemainsAvailableForManagement() {
        var durable=mock(OAuth2AuthorizationConsentService.class);
        var remembered=OAuth2AuthorizationConsent.withId("registration","person").scope("read").build();
        when(durable.findById("registration","person")).thenReturn(remembered);
        var ceremony=new FreshCimdConsentService(durable);
        assertThat(ceremony.findById("registration","person")).isSameAs(remembered);
        CimdClientContext.set(new CimdClientContext.Binding("https://ai.example/client","cimd-internal","registration"));
        try {
            assertThat(ceremony.findById("registration","person")).isNull();
            ceremony.save(remembered);ceremony.remove(remembered);
        } finally { CimdClientContext.clear(); }
        assertThat(ceremony.findById("registration","person")).isSameAs(remembered);
        verify(durable).save(remembered);verify(durable).remove(remembered);
    }
}
