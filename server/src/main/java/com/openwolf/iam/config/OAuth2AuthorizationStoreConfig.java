package com.openwolf.iam.config;

import com.openwolf.iam.auth.RedisOAuth2AuthorizationService;
import com.openwolf.iam.auth.AuthorizationTenantResolver;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;

@Configuration
public class OAuth2AuthorizationStoreConfig {

    @Bean
    public RedisTemplate<String, OAuth2Authorization> oauth2AuthorizationRedisTemplate(
            RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, OAuth2Authorization> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        template.setKeySerializer(RedisSerializer.string());
        template.setHashKeySerializer(RedisSerializer.string());
        template.setValueSerializer(new JdkSerializationRedisSerializer());
        template.setHashValueSerializer(new JdkSerializationRedisSerializer());
        template.afterPropertiesSet();
        return template;
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(
            RedisTemplate<String, OAuth2Authorization> oauth2AuthorizationRedisTemplate,
            StringRedisTemplate stringRedisTemplate,
            @Value("${iam.oauth2.authorization-store.redis.key-prefix:iam:oauth2}") String keyPrefix,
            @Value("${iam.oauth2.authorization-store.tenant-claim:tenant_id}") String tenantClaim,
            AuthorizationTenantResolver tenantResolver) {
        return new RedisOAuth2AuthorizationService(
                oauth2AuthorizationRedisTemplate, stringRedisTemplate, keyPrefix, tenantClaim, tenantResolver);
    }
}
