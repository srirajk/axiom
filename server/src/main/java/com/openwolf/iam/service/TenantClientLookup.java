package com.openwolf.iam.service;

import com.openwolf.iam.auth.CimdClientContext;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.repository.TenantApplicationClientRepository;
import java.util.Optional;

/** Shared product-registry lookup. External URLs require a server-selected application binding. Never fetches. */
public final class TenantClientLookup {
    private final TenantApplicationClientRepository clients;
    public TenantClientLookup(TenantApplicationClientRepository clients) { this.clients = clients; }
    public Optional<TenantApplicationClient> find(String clientId) {
        if (clientId != null && clientId.startsWith("https://")) {
            var binding = CimdClientContext.current();
            if (binding == null || !clientId.equals(binding.clientId())) return Optional.empty();
            return clients.findByClientId(binding.internalClientId()).filter(row -> clientId.equals(row.getExternalClientId()));
        }
        return clients.findByClientId(clientId);
    }
}
