package com.openwolf.iam.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

/**
 * Configures the primary {@link ObjectMapper}:
 * <ul>
 *   <li>Registers {@link JavaTimeModule} so {@link java.time.Instant} serialises as ISO-8601 string</li>
 *   <li>Disables {@code WRITE_DATES_AS_TIMESTAMPS}</li>
 *   <li>Disables {@code FAIL_ON_UNKNOWN_PROPERTIES} for forward-compatibility</li>
 * </ul>
 */
@Configuration
public class JacksonConfig {

    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        return new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    }
}
