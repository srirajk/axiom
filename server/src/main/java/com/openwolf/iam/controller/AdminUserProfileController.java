package com.openwolf.iam.controller;

import com.openwolf.iam.auth.ApplicationScopes;
import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.auth.SubjectContextCaller;
import com.openwolf.iam.dto.UserProfileLookupRequest;
import com.openwolf.iam.dto.UserProfileResponse;
import com.openwolf.iam.service.GroupService;
import com.openwolf.iam.service.UserService;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;

/** Narrow service-only profile API; never grants access to the wider admin API. */
@RestController
@RequestMapping("/admin")
public class AdminUserProfileController {
    /** Stable wire shape; do not serialize Spring Data's internal Page implementation. */
    public record MemberPage(List<UserProfileResponse> content, int page, int size,
                             long totalElements, boolean hasNext) {}

    private final ExecutionTenant tenant;
    private final SubjectContextCaller caller;
    private final UserService users;
    private final GroupService groups;

    public AdminUserProfileController(ExecutionTenant tenant, SubjectContextCaller caller,
                                      UserService users, GroupService groups) {
        this.tenant = tenant;
        this.caller = caller;
        this.users = users;
        this.groups = groups;
    }

    @PostMapping("/users/lookup")
    @PreAuthorize("hasAuthority('SCOPE_" + ApplicationScopes.USERS_READ_PROFILE + "')")
    public List<UserProfileResponse> lookup(@Valid @RequestBody UserProfileLookupRequest request) {
        caller.requireAuthorized(tenant.require(), ApplicationScopes.USERS_READ_PROFILE);
        return users.lookupProfiles(request.subjects());
    }

    @GetMapping("/groups/{groupId}/members")
    @PreAuthorize("hasAuthority('SCOPE_" + ApplicationScopes.USERS_READ_PROFILE + "')")
    public ResponseEntity<MemberPage> members(@PathVariable UUID groupId,
                                             @RequestParam(defaultValue = "0") int page,
                                             @RequestParam(defaultValue = "50") int size) {
        caller.requireAuthorized(tenant.require(), ApplicationScopes.USERS_READ_PROFILE);
        if (page < 0 || size < 1 || size > 100) {
            return ResponseEntity.badRequest().build();
        }
        Page<UserProfileResponse> result = groups.pageMemberProfiles(groupId, page, size);
        return ResponseEntity.ok(new MemberPage(result.getContent(), page, size,
                result.getTotalElements(), result.hasNext()));
    }
}
