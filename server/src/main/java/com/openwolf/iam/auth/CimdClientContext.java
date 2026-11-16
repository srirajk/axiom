package com.openwolf.iam.auth;

/** Server-selected binding for one synchronous OAuth request. Never populated from a client-supplied internal id. */
public final class CimdClientContext {
    public record Binding(String clientId, String internalClientId, String registeredClientId,
                          java.util.UUID applicationId, java.util.List<String> applicationScopes,
                          org.springframework.security.oauth2.server.authorization.client.RegisteredClient validatedClient,
                          org.springframework.security.oauth2.server.authorization.OAuth2Authorization authorization) {
        public Binding(String clientId, String internalClientId, String registeredClientId) {
            this(clientId, internalClientId, registeredClientId, null, null, null, null);
        }
        public Binding(String clientId, String internalClientId, String registeredClientId,
                       org.springframework.security.oauth2.server.authorization.client.RegisteredClient validatedClient,
                       org.springframework.security.oauth2.server.authorization.OAuth2Authorization authorization) {
            this(clientId, internalClientId, registeredClientId, null, null, validatedClient, authorization);
        }
    }
    private static final ThreadLocal<Binding> CURRENT = new ThreadLocal<>();
    private CimdClientContext() {}
    public static Binding current() { return CURRENT.get(); }
    static void set(Binding binding) { CURRENT.set(binding); }
    static void clear() { CURRENT.remove(); }
    public static String internalClientId(String clientId) {
        Binding binding = current();
        return binding != null && binding.clientId().equals(clientId) ? binding.internalClientId() : clientId;
    }
}
