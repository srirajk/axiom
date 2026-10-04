package com.openwolf.iam.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Serves the Axiom-branded OIDC login page.
 *
 * Spring Security's formLogin() redirects unauthenticated OIDC flows to /login.
 * The Thymeleaf template at templates/login.html handles CSRF token injection
 * and renders the Axiom brand identity.
 */
@Controller
public class LoginController {

    @GetMapping("/login")
    public String loginPage(@RequestParam(name = "error", required = false) String error, Model model) {
        model.addAttribute("loginError", error != null);
        return "login";
    }

    /**
     * Customer (CIAM) sign-in page, reached only from an authorization request of a customer-facing client. A separate
     * page and form for a separate population: workforce credentials are never accepted here and vice versa.
     */
    @GetMapping("/login/customer")
    public String customerLoginPage(@RequestParam(name = "error", required = false) String error, Model model) {
        model.addAttribute("loginError", error != null);
        return "customer-login";
    }
}
