# CipherPost on Kubernetes

Alternative to docker-compose for scaled enterprise rollout.

```bash
kubectl apply -f k8s/namespace.yaml
cp k8s/secret.yaml k8s/secret.local.yaml  # fill in real values (gitignored)
kubectl apply -f k8s/secret.local.yaml
kubectl apply -f k8s/configmap.yaml k8s/postgres-redis.yaml
kubectl apply -f k8s/backend.yaml k8s/frontend.yaml
# label SPAN-fed nodes, then:
kubectl label node <span-node> cipherpost/capture=true
kubectl apply -f k8s/capture-daemonset.yaml
```

Notes:
- Images: build & push `cipherpost/{api,worker,frontend}:latest` (see `docker/`).
- Small deployments can keep in-cluster Postgres/Redis; production should
  use managed services and point the Secret URLs at them.
- Scale analyzers with `queues.sessions` depth (`GET /api/v1/live/status`);
  the HPA also reacts to CPU. Consumer groups guarantee no duplicate work.
- Capture needs SPAN/TAP-fed interfaces on labeled nodes; `NET_RAW` +
  `NET_ADMIN` caps, no root.
