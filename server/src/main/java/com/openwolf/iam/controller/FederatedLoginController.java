package com.openwolf.iam.controller;

import com.openwolf.iam.entity.IdentitySource;
import com.openwolf.iam.federation.IdentitySourceClientRegistrationRepository;
import com.openwolf.iam.repository.IdentitySourceRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

/** Starts a browser login for one explicitly selected ACTIVE identity source. */
@Controller
public final class FederatedLoginController {
    private final IdentitySourceRepository sources;

    public FederatedLoginController(IdentitySourceRepository sources) { this.sources = sources; }

    @GetMapping("/login/identity/{sourceId}")
    public String login(@PathVariable UUID sourceId) {
        IdentitySource source = sources.findById(sourceId)
                .filter(value -> value.getStatus() == IdentitySource.Status.ACTIVE)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        return "redirect:/oauth2/authorization/" + IdentitySourceClientRegistrationRepository.registrationId(source);
    }
}
