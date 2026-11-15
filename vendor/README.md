# Vendored inputs and provenance

`manifest-lock.json` records exact upstream commits, URLs, versions and raw SHA256 values. All non-assembly inputs must be listed and present. Authored `kustomization.yaml` files only assemble these inputs; they are config-owned source, not upstream CRD modifications.

- Argo CD 3.6.1's three original CRDs, commit `94037c4d4e1af4bd0651d37a179fbd9e347e668c`; Apache-2.0 licence retained.
- Official Kubernetes v1.35.0 apiextensions OpenAPI v3 components, commit `66452049f3d692768c39c797b21b793dce80314e`; Apache-2.0 licence retained.
- Five strict standalone Kubernetes schema documents from yannh/kubernetes-json-schema, commit `2bfaff3898a7a4fa4e4760da3d2656211c9b4c71`. Original copyright/Apache-2.0 notice retained; full Apache text is in the Kubernetes licence file. GitHub's automatic NOASSERTION classification was resolved by reading the upstream notice.

`.gitattributes` preserves vendor bytes exactly. Do not edit upstream schemas/CRDs to make checks pass; review their source/version/hash/licence together. Tool restoration is separate from offline validation. This is neither an approved live cluster version nor a deployment/CVE assessment.
