package com.openwolf.iam.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import java.time.*;
import java.util.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class CimdDocumentsTest {
    static final String URL="https://ai.example/client.json";
    final ObjectMapper json=new ObjectMapper();
    final CimdHttpFetcher fetcher=mock(CimdHttpFetcher.class);
    final MutableClock clock=new MutableClock();
    final CimdDocuments cache=new CimdDocuments(fetcher,clock);
    final List<String> failures=new ArrayList<>();
    static class MutableClock extends Clock {
        Instant now=Instant.parse("2026-10-28T12:00:00Z");
        @Override public Instant instant(){return now;}
        @Override public ZoneId getZone(){return ZoneOffset.UTC;}
        @Override public Clock withZone(ZoneId zone){return this;}
    }
    Map<String,Object> document(){return new HashMap<>(Map.of("client_id",URL,"client_name","AI","redirect_uris",List.of("https://ai.example/callback"),
            "grant_types",List.of("authorization_code","refresh_token"),"token_endpoint_auth_method","none"));}
    CimdHttpFetcher.Response response(Map<String,Object> value,String policy)throws Exception {
        return new CimdHttpFetcher.Response(json.writeValueAsBytes(value),policy,0);
    }
    @Test void group6CacheUsesFreshDataThenStaleOnNetworkFailureButNeverAfter24Hours()throws Exception {
        when(fetcher.fetch(URL)).thenReturn(response(document(),"max-age=300"));
        var first=cache.get(URL,failures::add);clock.now=clock.now.plusSeconds(299);
        assertThat(cache.get(URL,failures::add)).isSameAs(first);verify(fetcher,times(1)).fetch(URL);
        clock.now=clock.now.plusSeconds(2);when(fetcher.fetch(URL)).thenThrow(new CimdHttpFetcher.FetchFailure("offline"));
        assertThat(cache.get(URL,failures::add)).isSameAs(first);assertThat(failures).containsExactly("retrieval");
        cache.get(URL,failures::add);verify(fetcher,times(2)).fetch(URL);
        clock.now=Instant.parse("2026-10-29T12:00:00Z");
        assertThatThrownBy(()->cache.get(URL,failures::add)).isInstanceOf(CimdHttpFetcher.FetchFailure.class);
        verify(fetcher,times(3)).fetch(URL);
    }
    @Test void invalidRefetchCannotHideBehindTheStaleCopy()throws Exception {
        when(fetcher.fetch(URL)).thenReturn(response(document(),"max-age=300"));cache.get(URL,failures::add);
        clock.now=clock.now.plusSeconds(301);var wrong=document();wrong.put("client_id","https://attacker.example/client");
        when(fetcher.fetch(URL)).thenReturn(response(wrong,"max-age=300"));
        assertThatThrownBy(()->cache.get(URL,failures::add)).isInstanceOf(IllegalArgumentException.class);
        assertThat(failures).containsExactly("invalid_metadata");
        when(fetcher.fetch(URL)).thenThrow(new CimdHttpFetcher.FetchFailure("offline"));
        assertThatThrownBy(()->cache.get(URL,failures::add)).isInstanceOf(CimdHttpFetcher.FetchFailure.class);
    }
    @Test void invalidDocumentsAreNeverCached()throws Exception {
        for(String field:List.of("client_id","client_name","redirect_uris","grant_types")) {
            var invalid=document();invalid.remove(field);when(fetcher.fetch(URL)).thenReturn(response(invalid,"max-age=86400"));
            assertThatThrownBy(()->cache.get(URL,failures::add)).as(field).isInstanceOf(IllegalArgumentException.class);
        }
        for(String field:List.of("client_secret","client_secret_expires_at","jwks")) {
            var invalid=document();invalid.put(field,Map.of());when(fetcher.fetch(URL)).thenReturn(response(invalid,"max-age=86400"));
            assertThatThrownBy(()->cache.get(URL,failures::add)).as(field).isInstanceOf(IllegalArgumentException.class);
        }
        when(fetcher.fetch(URL)).thenReturn(response(document(),"max-age=86400"));cache.get(URL,failures::add);
        verify(fetcher,times(8)).fetch(URL);
    }
    @Test void noStoreAndNoCacheAreRespectedAndAgeReducesFreshness()throws Exception {
        for(String directive:List.of("no-store","max-age=3600, no-cache")) {
            when(fetcher.fetch(URL)).thenReturn(response(document(),directive));cache.get(URL,failures::add);cache.get(URL,failures::add);
        }
        verify(fetcher,times(4)).fetch(URL);
        assertThat(CimdDocuments.freshness(new CimdHttpFetcher.Response(new byte[0],"max-age=1",0))).isEqualTo(Duration.ofMinutes(5));
        assertThat(CimdDocuments.freshness(new CimdHttpFetcher.Response(new byte[0],"max-age=999999",0))).isEqualTo(Duration.ofHours(24));
        assertThat(CimdDocuments.freshness(new CimdHttpFetcher.Response(new byte[0],"max-age=3600",3500))).isEqualTo(Duration.ofSeconds(100));
    }
    @Test void duplicateJsonKeysAndTrailingObjectsAreRejected() {
        for(String invalid:List.of("{\"client_id\":\"x\",\"client_id\":\"y\"}","{} {}")) {
            when(fetcher.fetch(URL)).thenReturn(new CimdHttpFetcher.Response(invalid.getBytes(java.nio.charset.StandardCharsets.UTF_8),"max-age=300",0));
            assertThatThrownBy(()->cache.get(URL,failures::add)).isInstanceOf(IllegalArgumentException.class);
        }
    }
}
