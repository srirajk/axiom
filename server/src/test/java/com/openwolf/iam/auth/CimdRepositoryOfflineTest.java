package com.openwolf.iam.auth;

import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.repository.TenantApplicationClientRepository;
import com.openwolf.iam.service.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import java.util.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class CimdRepositoryOfflineTest {
    @Test void byIdAndBoundByClientIdNeverFetchAndAReconstructedRepositoryKeepsIdentity() {
        String url="https://ai.example/client.json",internal="cimd-fixed",id=UUID.randomUUID().toString();UUID app=UUID.randomUUID();
        var stored=RegisteredClient.withId(id).clientId(internal).clientName("Admin-approved AI")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://127.0.0.1/callback").scope("openid").clientSettings(ClientSettings.builder()
                        .setting(CimdRegisteredClientRepository.CLIENT_ID,url).requireAuthorizationConsent(true).build()).build();
        var storage=new InMemoryRegisteredClientRepository(stored);var clients=mock(TenantApplicationClientRepository.class);
        var row=new TenantApplicationClient(app,internal,TenantApplicationClient.Type.PUBLIC_BROWSER,List.of("openid"));row.trustExternalClient(url);
        when(clients.findByClientId(internal)).thenReturn(Optional.of(row));
        var applications=mock(TenantApplicationService.class);when(applications.activeAuthority(internal)).thenReturn(Optional.of(
                new TenantApplicationService.ClientAuthority("tenant-a","https://resource.example",TenantApplicationClient.Type.PUBLIC_BROWSER,List.of("openid"),app,TenantApplicationClient.Population.WORKFORCE)));
        var fetcher=mock(CimdHttpFetcher.class);var documents=new CimdDocuments(fetcher);var audit=mock(AuditService.class);
        var beans=new StaticListableBeanFactory();beans.addBean("applications",applications);beans.addBean("audit",audit);
        for(int i=0;i<2;i++) {
            var repository=new CimdRegisteredClientRepository(storage,beans.getBeanProvider(TenantApplicationService.class),clients,documents,beans.getBeanProvider(AuditService.class));
            assertThat(repository.findById(id).getClientId()).isEqualTo(url);
            assertThat(repository.findById(id).getId()).isEqualTo(id);
            assertThat(repository.findByClientId(internal)).isNull();
            CimdClientContext.set(new CimdClientContext.Binding(url,internal,id));
            try { assertThat(repository.findByClientId(url).getId()).isEqualTo(id); } finally { CimdClientContext.clear(); }
        }
        verifyNoInteractions(fetcher);
    }
}
