package com.openwolf.iam.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Test;
import java.time.*;
import java.util.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class CimdKeyRotationTest {
    static final String URL="https://ai.example/client.json", JWKS="https://ai.example/jwks.json";
    final ObjectMapper json=new ObjectMapper();
    final CimdHttpFetcher fetcher=mock(CimdHttpFetcher.class);
    final CimdDocumentsTest.MutableClock clock=new CimdDocumentsTest.MutableClock();
    final CimdDocuments documents=new CimdDocuments(fetcher,clock);
    final List<String> failures=new ArrayList<>();
    CimdHttpFetcher.Response response(Map<String,Object> body,String cache)throws Exception {
        return new CimdHttpFetcher.Response(json.writeValueAsBytes(body),cache,0);
    }
    CimdDocuments.Document metadata()throws Exception {
        when(fetcher.fetch(URL)).thenReturn(response(Map.of("client_id",URL,"client_name","AI","redirect_uris",List.of("https://ai.example/callback"),
                "grant_types",List.of("authorization_code"),"token_endpoint_auth_method","private_key_jwt","jwks_uri",JWKS),"max-age=86400"));
        return documents.get(URL,failures::add);
    }
    @Test void metadataDoesNotLoadKeysAndExpiredKeysHaveNoStaleFallback()throws Exception {
        var metadata=metadata();verify(fetcher,never()).fetch(JWKS);
        var key=new RSAKeyGenerator(2048).keyID("old").generate();
        when(fetcher.fetch(JWKS)).thenReturn(response(Map.of("keys",List.of(key.toPublicJWK().toJSONObject())),"max-age=86400"));
        assertThat(documents.keys(metadata,"old",failures::add).keyIds()).containsExactly("old");
        clock.now=clock.now.plusSeconds(299);documents.keys(metadata,"old",failures::add);verify(fetcher,times(1)).fetch(JWKS);
        clock.now=clock.now.plusSeconds(2);when(fetcher.fetch(JWKS)).thenThrow(new CimdHttpFetcher.FetchFailure("offline"));
        assertThatThrownBy(()->documents.keys(metadata,"old",failures::add)).isInstanceOf(CimdHttpFetcher.FetchFailure.class);
        assertThat(failures).containsExactly("jwks_retrieval_or_validation");
        assertThat(documents.get(URL,failures::add)).isSameAs(metadata);verify(fetcher,times(1)).fetch(URL);
    }
    @Test void unknownKidRefreshesOnceThenRateLimitsWhileRevokedKeysStayAbsent()throws Exception {
        var metadata=metadata();var old=new RSAKeyGenerator(2048).keyID("old").generate();var next=new RSAKeyGenerator(2048).keyID("new").generate();
        when(fetcher.fetch(JWKS)).thenReturn(response(Map.of("keys",List.of(old.toPublicJWK().toJSONObject())),"max-age=300"));
        documents.keys(metadata,"old",failures::add);
        when(fetcher.fetch(JWKS)).thenReturn(response(Map.of("keys",List.of(next.toPublicJWK().toJSONObject())),"max-age=300"));
        assertThat(documents.keys(metadata,"new",failures::add).keyIds()).containsExactly("new");
        assertThat(documents.keys(metadata,"old",failures::add).keyIds()).doesNotContain("old");
        for(int i=0;i<10;i++)documents.keys(metadata,"unknown-"+i,failures::add);
        verify(fetcher,times(2)).fetch(JWKS);
        clock.now=clock.now.plusSeconds(31);documents.keys(metadata,"another",failures::add);verify(fetcher,times(3)).fetch(JWKS);
    }
    @Test void noStoreAndInvalidPrivateKeysAreNeverCached()throws Exception {
        var metadata=metadata();var key=new RSAKeyGenerator(2048).keyID("key").generate();
        when(fetcher.fetch(JWKS)).thenReturn(response(Map.of("keys",List.of(key.toPublicJWK().toJSONObject())),"no-store"));
        documents.keys(metadata,"key",failures::add);documents.keys(metadata,"key",failures::add);verify(fetcher,times(2)).fetch(JWKS);
        when(fetcher.fetch(JWKS)).thenReturn(response(Map.of("keys",List.of(key.toJSONObject())),"max-age=86400"));
        assertThatThrownBy(()->documents.keys(metadata,"key",failures::add)).isInstanceOf(IllegalArgumentException.class);
        when(fetcher.fetch(JWKS)).thenThrow(new CimdHttpFetcher.FetchFailure("offline"));
        assertThatThrownBy(()->documents.keys(metadata,"key",failures::add)).isInstanceOf(CimdHttpFetcher.FetchFailure.class);
    }
    @Test void displayNamesCannotCarryControlsOrBidiAndKeysRespectShortCachePolicy() {
        assertThat(CimdDocuments.safeDisplayName("Safe\u202e\u0000\n App")).isEqualTo("Safe App");
        assertThat(CimdDocuments.safeDisplayName("a".repeat(100))).hasSize(80);
        assertThatThrownBy(()->CimdDocuments.safeDisplayName("\u202e\u0000")).isInstanceOf(IllegalArgumentException.class);
        assertThat(CimdDocuments.keyFreshness(new CimdHttpFetcher.Response(new byte[0],"max-age=10",0))).isEqualTo(Duration.ofSeconds(10));
        assertThat(CimdDocuments.keyFreshness(new CimdHttpFetcher.Response(new byte[0],"max-age=99999",0))).isEqualTo(Duration.ofMinutes(5));
        assertThat(CimdDocuments.freshness(new CimdHttpFetcher.Response(new byte[0],"max-age=0",0))).isZero();
    }
    @Test void privateAssertionCannotReuseAStaleKeyDelegationDocument()throws Exception {
        var original=metadata();clock.now=clock.now.plusSeconds(301);
        when(fetcher.fetch(URL)).thenThrow(new CimdHttpFetcher.FetchFailure("offline"));
        assertThatThrownBy(()->documents.forAuthentication(URL,failures::add)).isInstanceOf(CimdHttpFetcher.FetchFailure.class);
        assertThat(documents.get(URL,failures::add)).isSameAs(original);
        verify(fetcher,times(2)).fetch(URL);
    }
}
