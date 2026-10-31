# Shared local Envoy edge

This chart installs the fixed Docker Desktop Meridian edge profile: `gateway-demo/axiom-local-proxy`,
`axiom-local-gateway`, Axiom's Gateway, four HTTPRoutes and its backend ReferenceGrant. All Gateways using this
class share one Envoy deployment and one LoadBalancer on ports 80/443. Each application owns its listeners,
routes and certificates. New Gateways must omit `spec.infrastructure.parametersRef` and use
`spec.gatewayClassName: axiom-local-gateway`.

The normal [local installer](../../axiom-local-edge/README.md) installs this chart as release `axiom-local-edge`
in `gateway-demo` on a fresh cluster, after the pinned Envoy Gateway controller and CRDs are installed. It preserves
the ownership of older manifest installations and applies the same rendered chart to those installations.
`deploy/axiom-local-edge/gateway.yaml` links to this chart's template so the two paths cannot drift.

The `axiom` and `gateway-demo` namespaces, Axiom backend Services, and existing `axiom-identity-tls` and
`axiom-admin-tls` Secrets must exist first. This chart creates no certificate, key, credential, controller or
database. It is a fixed local testing profile; hostnames and the LoadBalancer are unsuitable as production defaults.

For a new estate whose prerequisites are already installed:

```bash
helm lint deploy/helm/axiom-local-edge
helm template axiom-local-edge deploy/helm/axiom-local-edge -n gateway-demo
helm upgrade --install axiom-local-edge deploy/helm/axiom-local-edge \
  --kube-context docker-desktop -n gateway-demo --atomic --wait --timeout 5m
```

Run the normal installer's `status` and HTTPS checks afterward; Helm alone does not wait for Gateway conditions.
An existing release can be rolled back with Helm. Uninstalling this shared edge removes Axiom's routes and the
GatewayClass used by other applications, so preserve it while any application uses the class.
