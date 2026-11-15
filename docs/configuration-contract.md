# Configuration contract and remaining integration

Config is the sole author of these namespace/foundation policy/RBAC and selected CRD definitions. It creates no ServiceAccount, RoleBinding, Deployment, application chart, Azure resource or Argo Application. Each workload namespace has an unbound reviewer Role: get/list on selected pods/services/events/deployments/replicasets, without secrets, configmaps, logs, exec, watch, impersonation, bind/escalate or writes. A Role alone grants nobody access. RBAC does not filter returned content; future monitoring adapters still need metadata-only capture and bounds.

## Logical profiles

- Dev owns `ai-lab-dev`; QA owns `ai-lab-qa`. Each composes namespace, quota, container defaults, Role and network policies.
- Platform owns `argocd`/`ai-observability`, observability network policies and the original three Argo 3.6.1 CRDs. It installs no controller. Namespace/CRD emission is disabled in the chart dependency scaffold.
- All four namespace declarations request restricted Pod Security Admission at v1.35. Actual controller/workload pod compatibility and admission must be verified before rollout. Workload quotas bound CPU/memory, ten pods/services and zero PVC/LoadBalancer/NodePort objects; these source bounds are not Azure sizing/cost evidence.

## Network contract

Default deny covers ingress and egress in both workload namespaces and observability. Explicit edges allow DNS to labelled kube-dns pods in kube-system, a synthetic test-client -> agent -> retrieval chain within one workload namespace (TCP 8080), OTLP to Collector (4317/4318), and Collector -> Jaeger (4317). No public IP block, wildcard namespace or unbounded port rule is accepted. APIM egress remains closed until its exact target/identity/network contract is verified; no direct-model fallback is added.

Future application charts must use `app.kubernetes.io/part-of: ai-lab` and component `agent`, `retrieval` or `test-client`. Backend charts must use `app.kubernetes.io/name: otel-collector` or `jaeger`. Workload namespaces carry `ai-lab.example/workload: "true"`. These are selectors/contracts, not working-pod evidence. DNS assumes reviewed kube-dns labels; NodeLocal DNS/other cluster behavior needs an explicit verified change. Argo controller networking remains to implement before any installation. Jaeger UI exposure is not added.

## Offline validation boundary

The validator verifies vendored raw hashes/licences, rejects remote/escaping Kustomize inputs and generators, uses checksum-verified Kustomize, builds three profiles and checks schema/scope/ownership. Duplicate identities across API versions, unsafe RBAC, unapproved namespace/network allowances and weakened default deny fail. It explicitly applies Draft 4 keyword checks to locked swagger-derived standalone schema# inputs and official Kubernetes OpenAPI components; unknown dialects fail and remote schema retrieval is forbidden.

This does not execute Kubernetes admission/CEL, prove structural CRD installation or enforce NetworkPolicy/PSA. No bootstrap handover, identity grant, application traffic, image digest or release acceptance is inferred. Later P2.13 charts/GitOps and combined handover checks remain; actual AKS support/targets and cloud gates must be rechecked before deployment.
