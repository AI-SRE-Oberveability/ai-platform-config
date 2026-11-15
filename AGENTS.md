# Configuration working agreement

Follow the approved ai-platform-lab/docs/platform-ownership-plan.md and current HLD/tracker in the sibling lab. This repository owns namespace/foundation policy/RBAC and selected CRD source, not Azure resources or chart-owned service accounts/deployments. Keep one source owner and one active spec writer per object.

Work offline by default. Never apply manifests, contact a cluster/Azure, enable deployment or change GitLab credentials/helpers/remotes/global Git configuration during source validation. Use synthetic identities only; do not commit Secret values, kubeconfig, auth files or raw captures. Preserve vendored byte hashes/licences and the original lab evidence. Record source, actual checks and limitations in the lab after each step.
