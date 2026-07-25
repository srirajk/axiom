package com.openwolf.iam.auth;

import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.entity.Role;
import com.openwolf.iam.repository.PrincipalRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Loads {@link UserDetails} for Spring Security's {@link org.springframework.security.authentication.AuthenticationManager}.
 * Used by both form login (AUTHORIZATION_CODE flow) and the custom {@code /auth/login} endpoint.
 */
@Service
@Transactional(readOnly = true)
public class CustomUserDetailsService implements UserDetailsService {

    private static final Logger log = LoggerFactory.getLogger(CustomUserDetailsService.class);

    private final PrincipalRepository principalRepository;

    public CustomUserDetailsService(PrincipalRepository principalRepository) {
        this.principalRepository = principalRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Principal principal = principalRepository.findByUsername(username)
                .orElseThrow(() -> {
                    log.warn("Login attempt for unknown username: {}", username);
                    return new UsernameNotFoundException("User not found: " + username);
                });

        if (!principal.isActive()) {
            log.warn("Login attempt for inactive principal: {}", username);
            throw new UsernameNotFoundException("Account is disabled: " + username);
        }

        List<SimpleGrantedAuthority> authorities = principal.getRoles().stream()
                .map(Role::getName)
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .toList();

        return User.builder()
                .username(principal.getId())         // use ID as the security principal name (sub)
                .password(principal.getPasswordHash())
                .authorities(authorities)
                .accountLocked(!principal.isActive())
                .build();
    }
}
