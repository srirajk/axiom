package com.openwolf.iam.controller;

import com.openwolf.iam.dto.CiamContracts.CustomerAuthenticationRequest;
import com.openwolf.iam.dto.CiamContracts.RegisterCustomerRequest;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;

import static org.assertj.core.api.Assertions.assertThat;

class CiamControllerContractTest {
    @Test
    void customerBootstrapAndTokenRoutesAreExplicitWhileDelegationIsSubjectProtected() throws Exception {
        assertThat(CiamCustomerController.class.getMethod("register", String.class,
                RegisterCustomerRequest.class, HttpServletRequest.class)
                .getAnnotation(PostMapping.class).value()).containsExactly("/registrations");
        assertThat(CiamCustomerController.class.getMethod("token", String.class,
                CustomerAuthenticationRequest.class, HttpServletRequest.class)
                .getAnnotation(PostMapping.class).value())
                .containsExactly("/tokens");
        assertThat(CiamDelegationController.class.getAnnotation(PreAuthorize.class).value())
                .contains("authentication.name == #customerId.toString()");
        assertThat(CiamAdminController.class.getAnnotation(PreAuthorize.class).value())
                .contains("platform_admin");
    }
}
