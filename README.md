# AI platform configuration

Configuration source for the personal AI/SRE lab: namespaces, scoped policy/RBAC and selected vendored CRDs. Source ownership is defined in the approved lab P2.13 plan. Terraform owns Azure/APIM; charts own controller/application templates; GitOps selects immutable releases. Configuration files alone are not deployment or backend evidence.

Azure deployment remains disabled. No Kubernetes context, account identity or cloud target is configured by this repository. Follow the lab HLD/tracker for current acceptance and keep GitLab credentials/global Git settings intact.
