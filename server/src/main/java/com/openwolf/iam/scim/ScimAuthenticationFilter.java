package com.openwolf.iam.scim;

import com.openwolf.iam.entity.ScimProvisioningSource;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class ScimAuthenticationFilter extends OncePerRequestFilter {
    public static final String SOURCE_ATTRIBUTE = ScimAuthenticationFilter.class.getName() + ".source";
    private final ScimCredentialService credentials;
    public ScimAuthenticationFilter(ScimCredentialService credentials) { this.credentials = credentials; }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/scim/v2/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            reject(response); return;
        }
        try {
            ScimProvisioningSource source = credentials.authenticate(header.substring(7).trim());
            request.setAttribute(SOURCE_ATTRIBUTE, source);
            var authentication = new UsernamePasswordAuthenticationToken(source, null,
                    AuthorityUtils.createAuthorityList("ROLE_SCIM_PROVISIONER"));
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        } catch (ScimException ex) {
            reject(response);
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    private static void reject(HttpServletResponse response) throws IOException {
        response.setStatus(401); response.setContentType("application/scim+json"); response.setHeader("WWW-Authenticate", "Bearer");
        response.getWriter().write("{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:Error\"],\"detail\":\"Invalid bearer credential\",\"status\":\"401\"}");
    }
}
