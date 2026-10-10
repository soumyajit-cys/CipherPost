# Task 8 evidence: Helm validation (local, no cluster) — 2026-10-10

Tools: `helm v4.0.0`, `kubeconform v0.8.0`, Python 3.13 (yaml parse).
Cluster install remains NOT-VERIFIED (kind workflow not run; see
`docs/evidence/kind-install.md`).

## Commands run

```bash
helm lint deploy/helm/cipherpost
# 1 chart linted, 0 failed (1 info: Chart.yaml icon recommended)

helm template cp-ci deploy/helm/cipherpost --namespace cipherpost \
  --set postgres.bundled.enabled=true --set redis.bundled.enabled=true > /tmp/cp-ci.yaml
helm template cp-full deploy/helm/cipherpost --namespace cipherpost \
  --set ingress.enabled=true --set monitoring.serviceMonitor.enabled=true \
  --set monitoring.prometheusRules.enabled=true \
  --set postgres.bundled.enabled=true --set redis.bundled.enabled=true \
  --set autoscaling.analyzer.enabled=false > /tmp/cp-full.yaml
helm template cp-nodb deploy/helm/cipherpost --namespace cipherpost
# exits 1 with "no database configured" (fail-fast validations.yaml OK)

kubeconform -strict -summary /tmp/cp-ci.yaml
kubeconform -summary -skip ServiceMonitor,PrometheusRule /tmp/cp-full.yaml
```

## Results (after fix)

- `cp-ci.yaml`: 18 resources — Valid: 18, Invalid: 0, Errors: 0.
- `cp-full.yaml`: 20 resources — Valid: 18, Invalid: 0, Errors: 0, Skipped: 2
  (ServiceMonitor/PrometheusRule operator CRDs without public schemas).
- Negative test: database-less values fail with `no database configured`.

## Bug found and fixed

Missing `---` document separator between the postgres Service and the redis
Deployment in `deploy/helm/cipherpost/templates/bundled.yaml` when both
bundled deps are enabled. Before the fix, `kubeconform -strict` reported:

> `cp-ci-redis failed validation: error unmarshalling resource ... key
> "apiVersion" already set in map` — 17 resources, Valid: 16, Errors: 1.

The postgres Service doc and redis Deployment doc were merged into one YAML
document. Fix: `---` separator before the redis Deployment block
(one-line change; fail-before/pass-after verified by re-running the commands
above: 16+1 error → 18/18 valid). No other chart values changed.

## Still NOT-VERIFIED (needs cluster/owner)

- `kind install` end-to-end (probes, migrations, ingest, smoke test).
- Registry-qualified images / pull secrets, HPA min/max behavior under load,
  probe tuning, bundled Redis auth/persistence, StatefulSet storageClassName,
  resource/securityContext parity for bundled pods — listed in
  `docs/evidence/kind-install.md` remaining gaps, unchanged here.
- Do NOT claim the chart installs successfully.

Last verified: 2026-10-10, helm v4.0.0 + kubeconform v0.8.0 locally.
