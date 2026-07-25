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
}
