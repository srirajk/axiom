package com.openwolf.iam.authority.issuer;

import com.openwolf.iam.IamApplication;
import com.openwolf.iam.authority.AuthorityITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** Story 0.6 switch: with legacy password login and impersonation disabled, those endpoints are absent (404). */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK,
        properties = {"iam.auth.legacy-password-login.enabled=false", "iam.auth.impersonation.enabled=false"})
@AutoConfigureMockMvc
class LegacyLoginSwitchIT extends AuthorityITSupport {

    @Test
    void legacyPasswordLoginAndImpersonationCanBeSwitchedOff() throws Exception {
        for (String path : new String[]{"/auth/login", "/auth/token"}) {
            int status = mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON)
                    .content(json.writeValueAsString(Map.of("username", "anyone", "password", "irrelevant-12345"))))
                    .andReturn().getResponse().getStatus();
            assertThat(status).as(path).isEqualTo(404);
        }
    }
}
