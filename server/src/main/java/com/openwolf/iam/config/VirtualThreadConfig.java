package com.openwolf.iam.config;

import org.apache.coyote.ProtocolHandler;
import org.springframework.boot.web.embedded.tomcat.TomcatProtocolHandlerCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.core.task.support.TaskExecutorAdapter;

import java.util.concurrent.Executors;

/**
 * Configures Tomcat to dispatch every request on a virtual thread.
 * Combined with {@code spring.threads.virtual.enabled=true}, this means
 * every blocking I/O (JDBC, gRPC to Cerbos, HTTP to agents) parks the
 * virtual thread and unmounts from the carrier — no platform thread is
 * consumed while waiting.
 */
@Configuration
public class VirtualThreadConfig {

    /**
     * Replaces Tomcat's default platform-thread executor with one that creates
     * a new virtual thread per task. Each HTTP request gets its own virtual thread.
     */
    @Bean
    public TomcatProtocolHandlerCustomizer<?> virtualThreadTomcatCustomizer() {
        return (ProtocolHandler protocolHandler) ->
                protocolHandler.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    }

    /**
     * Spring's {@link AsyncTaskExecutor} backed by virtual threads — used
     * internally by Spring MVC for {@code @Async} task execution.
     */
    @Bean
    public AsyncTaskExecutor applicationTaskExecutor() {
        return new TaskExecutorAdapter(Executors.newVirtualThreadPerTaskExecutor());
    }
}
