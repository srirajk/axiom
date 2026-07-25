package com.openwolf.iam.controller;

import com.openwolf.iam.dto.StatsResponse;
import com.openwolf.iam.repository.GroupRepository;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.repository.RoleRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Quick aggregate statistics — used by the admin-ui dashboard.
 */
@RestController
@RequestMapping("/stats")
public class StatsController {

    private final PrincipalRepository principalRepository;
    private final RoleRepository roleRepository;
    private final GroupRepository groupRepository;
    public StatsController(PrincipalRepository principalRepository,
                           RoleRepository roleRepository,
                           GroupRepository groupRepository) {
        this.principalRepository = principalRepository;
        this.roleRepository = roleRepository;
        this.groupRepository = groupRepository;
    }

    @GetMapping
    @Transactional(readOnly = true)
    public ResponseEntity<StatsResponse> stats() {
        return ResponseEntity.ok(new StatsResponse(
                principalRepository.count(),
                roleRepository.count(),
                groupRepository.count()
        ));
    }
}
