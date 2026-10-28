package com.openwolf.iam.auth;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.InputStreamEntity;
import org.apache.hc.core5.http.message.BasicClassicHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.junit.jupiter.api.Test;
import java.io.*;
import java.net.InetAddress;
import java.time.Duration;
import java.util.List;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class CimdHttpFetcherTest {
    @Test void group5AllRestrictedAddressesAndMixedDnsAnswersAreRefused()throws Exception {
        for(String value:List.of("10.0.0.1","127.0.0.1","169.254.169.254","168.63.129.16","172.16.0.1","192.168.1.1","0.0.0.0",
                "100.64.0.1","224.0.0.1","::1","fc00::1","fe80::1","::ffff:10.0.0.1","64:ff9b::a00:1","2002:a00:1::1","2001:db8::1")) {
            assertThatThrownBy(()->CimdHttpFetcher.requirePublic(new InetAddress[]{InetAddress.getByName(value)})).as(value).isInstanceOf(IllegalArgumentException.class);
        }
        CimdHttpFetcher.requirePublic(new InetAddress[]{InetAddress.getByName("8.8.8.8"),InetAddress.getByName("2606:4700:4700::1111")});
        assertThatThrownBy(()->CimdHttpFetcher.requirePublic(new InetAddress[]{InetAddress.getByName("8.8.8.8"),InetAddress.getByName("10.0.0.1")})).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void urlsRequireHttpsPathAndPublicDnsWithoutUserInfoQueryOrFragment() {
        for(String value:List.of("http://ai.example/client","https://ai.example","https://user@ai.example/client","https://ai.example/a/../client",
                "https://ai.example:8443/client","https://ai.example/a/%2e%2e/client","https://ai.example/client?x=1","https://ai.example/client#x","https://127.0.0.1/client","https://[::1]/client")) {
            assertThatThrownBy(()->CimdHttpFetcher.requireUrl(value)).as(value).isInstanceOf(IllegalArgumentException.class);
        }
        assertThat(CimdHttpFetcher.requireUrl("https://ai.example/client").getHost()).isEqualTo("ai.example");
    }
    @SuppressWarnings("unchecked")
    static CloseableHttpClient client(BasicClassicHttpResponse response)throws Exception {
        CloseableHttpClient client=mock(CloseableHttpClient.class);
        when(client.execute(any(HttpGet.class),any(HttpClientResponseHandler.class))).thenAnswer(invocation -> {
            HttpClientResponseHandler<CimdHttpFetcher.Response> handler=invocation.getArgument(1);
            return handler.handleResponse(response);
        });return client;
    }
    static BasicClassicHttpResponse response(int status,String type,InputStream stream) {
        var response=new BasicClassicHttpResponse(status);response.setHeader("Content-Type",type);
        response.setEntity(new InputStreamEntity(stream,-1,ContentType.APPLICATION_JSON));return response;
    }
    @Test void group5RedirectIsRefusedWithoutFollowingItsDestination()throws Exception {
        var response=response(302,"application/json",new ByteArrayInputStream(new byte[0]));response.setHeader("Location","https://internal.example/secret");
        var client=client(response);try(var fetcher=new CimdHttpFetcher(client)) {
            assertThatThrownBy(()->fetcher.fetch("https://ai.example/client")).isInstanceOf(IllegalArgumentException.class);
            verify(client,times(1)).execute(any(HttpGet.class),any(HttpClientResponseHandler.class));
        }
    }
    @Test void group5OversizeStreamingBodyIsStoppedAtTheCap()throws Exception {
        class Endless extends InputStream { int read;@Override public int read(){read++;return 'x';} }
        Endless stream=new Endless();var client=client(response(200,"application/json",stream));
        try(var fetcher=new CimdHttpFetcher(client)) {
            assertThatThrownBy(()->fetcher.fetch("https://ai.example/client")).isInstanceOf(IllegalArgumentException.class);
            assertThat(stream.read).isEqualTo(65537);
        }
    }
    @Test void requiresJsonAndAcceptsExactly64Kb()throws Exception {
        try(var fetcher=new CimdHttpFetcher(client(response(200,"text/html",new ByteArrayInputStream(new byte[0]))))) {
            assertThatThrownBy(()->fetcher.fetch("https://ai.example/client")).isInstanceOf(IllegalArgumentException.class);
        }
        try(var fetcher=new CimdHttpFetcher(client(response(200,"application/json; charset=utf-8",new ByteArrayInputStream(new byte[65536]))))) {
            assertThat(fetcher.fetch("https://ai.example/client").body()).hasSize(65536);
        }
    }
    @Test void totalDeadlineReturnsEvenIfTheNetworkWorkerIsBlocked()throws Exception {
        var client=client(response(200,"application/json",new ByteArrayInputStream(new byte[0])));
        when(client.execute(any(HttpGet.class),any(HttpClientResponseHandler.class))).thenAnswer(invocation->{Thread.sleep(10000);return null;});
        try(var fetcher=new CimdHttpFetcher(client)) {
            long start=System.nanoTime();
            assertThatThrownBy(()->fetcher.fetch("https://ai.example/client")).isInstanceOf(CimdHttpFetcher.FetchFailure.class);
            assertThat(Duration.ofNanos(System.nanoTime()-start)).isLessThan(Duration.ofSeconds(7));
        }
    }
    @Test void dnsRebindingCannotSwapTheCheckedAddressesBeforeConnection()throws Exception {
        var publicAnswer=new InetAddress[]{InetAddress.getByName("8.8.8.8")};
        var privateAnswer=new InetAddress[]{InetAddress.getByName("10.0.0.1")};
        var calls=new java.util.concurrent.atomic.AtomicInteger();
        CimdHttpFetcher.AddressResolver flipping=host->calls.incrementAndGet()==1?publicAnswer:privateAnswer;
        assertThat(CimdHttpFetcher.resolvePublic("changing.example",flipping)).isSameAs(publicAnswer);
        assertThat(calls.get()).isEqualTo(1);
        assertThatThrownBy(()->CimdHttpFetcher.resolvePublic("changing.example",flipping)).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void acceptsApplicationJsonSuffixMediaType()throws Exception {
        try(var fetcher=new CimdHttpFetcher(client(response(200,"application/oauth-client+json",new ByteArrayInputStream("{}".getBytes(java.nio.charset.StandardCharsets.UTF_8)))))) {
            assertThat(fetcher.fetch("https://ai.example/client").body()).hasSize(2);
        }
    }
}
