package com.openwolf.iam.bootstrap;

import com.openwolf.iam.repository.AuditLogRepository;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.repository.RoleRepository;
import com.openwolf.iam.repository.TenantRepository;
import com.openwolf.iam.service.AuditService;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundleRepository;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import com.openwolf.iam.tenancy.TenantNamespaceAdapter;
import com.openwolf.iam.tenancy.TenantProvisioningService;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;

import javax.sql.DataSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * AXM-107 packaged-runtime regression: transactional identity advice must be proxyable while the
 * runner remains non-transactional, so no identity transaction spans policy or Redis calls.
 */
class FirstTenantBootstrapRunnerContextTest {

    @Test
    void transactionalBootstrapRunnerIsProxyable() {
        new ApplicationContextRunner()
                .withUserConfiguration(TransactionProxyConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    Object identity = context.getBean(FirstTenantIdentityBootstrapService.class);
                    Object runner = context.getBean(FirstTenantBootstrapRunner.class);
                    assertThat(AopUtils.isAopProxy(identity)).isTrue();
                    assertThat(runner).isInstanceOf(FirstTenantBootstrapRunner.class);
                });
    }

    @Configuration(proxyBeanMethods = false)
    @EnableTransactionManagement(proxyTargetClass = true)
    static class TransactionProxyConfiguration {

        @Bean
        DataSource dataSource() {
            return new EmbeddedDatabaseBuilder()
                    .setType(EmbeddedDatabaseType.H2)
                    .build();
        }

        @Bean
        PlatformTransactionManager transactionManager(DataSource dataSource) {
            return new DataSourceTransactionManager(dataSource);
        }

        @Bean
        FirstTenantBootstrapRunner bootstrapRunner(
                FirstTenantIdentityBootstrapService identityBootstrap,
                TenantProvisioningService provisioning,
                ActiveTenantDirectory activeTenants,
                TenantNamespaceAdapter namespaces,
                PolicyBundleRepository policyBundles) {
            return new FirstTenantBootstrapRunner(identityBootstrap, provisioning, activeTenants, namespaces,
                    policyBundles);
        }

        @Bean
        FirstTenantIdentityBootstrapService identityBootstrap(
                TenantRepository tenants,
                RoleRepository roles,
                PrincipalRepository principals,
                AuditLogRepository audits,
                PasswordEncoder passwords,
                AuditService audit) {
            return new FirstTenantIdentityBootstrapService(tenants, roles, principals, audits, passwords, audit);
        }

        @Bean TenantProvisioningService provisioning() { return mock(TenantProvisioningService.class); }

        @Bean ActiveTenantDirectory activeTenants() { return mock(ActiveTenantDirectory.class); }

        @Bean TenantNamespaceAdapter namespaces() { return mock(TenantNamespaceAdapter.class); }

        @Bean PolicyBundleRepository policyBundles() { return mock(PolicyBundleRepository.class); }

        @Bean
        TenantRepository tenants() { return mock(TenantRepository.class); }

        @Bean
        RoleRepository roles() { return mock(RoleRepository.class); }

        @Bean
        PrincipalRepository principals() { return mock(PrincipalRepository.class); }

        @Bean
        AuditLogRepository audits() { return mock(AuditLogRepository.class); }

        @Bean
        PasswordEncoder passwords() { return PasswordEncoderFactories.createDelegatingPasswordEncoder(); }

        @Bean
        AuditService audit() { return mock(AuditService.class); }
    }
}
