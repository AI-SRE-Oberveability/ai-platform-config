# AI platform configuration

Configuration source for the personal AI/SRE lab: namespaces, scoped policy/RBAC and selected vendored CRDs. Source ownership is defined in the approved lab P2.13 plan. Terraform owns Azure/APIM; charts own controller/application templates; GitOps selects immutable releases. Configuration files alone are not deployment or backend evidence.

Azure deployment remains disabled. No Kubernetes context, account identity or cloud target is configured by this repository. Follow the lab HLD/tracker for current acceptance and keep GitLab credentials/global Git settings intact.

The three profiles build 32 unique objects: four Namespaces, two ResourceQuotas, two LimitRanges, two unbound read-only Roles, nineteen NetworkPolicies and three Argo CD 3.6.1 CRDs. Their offline API/schema baseline is Kubernetes 1.35.0; this does not select an actual AKS deployment version.

## Validate a clean checkout

Use Python 3.12 in a private virtual environment outside Git. Install `requirements-ci.txt` with `python -m pip install --require-hashes -r requirements-ci.txt`, then run:

```text
python scripts/tools.py
python -m unittest discover -s tests -v
python scripts/validate_config.py
```

Tool restoration explicitly downloads only checksum-locked Kustomize 5.8.3 to the parent's `.runtime/config-tools`. Set `CONFIG_TOOL_CACHE` to another private location outside Git if needed. The validator uses vendored schemas without network retrieval and never calls kubectl, Argo, Terraform or Azure. Linux/Windows CI has read-only permissions and no deployment/OIDC identity. Global tools are unchanged.

See [the configuration contract](docs/configuration-contract.md), [vendored provenance](vendor/README.md), `vendor/manifest-lock.json` and `locks/toolchain.json`. These checks do not prove live admission, networking, pod readiness or backend ingestion. Actual Azure targets/version, identities, networking, costs and deployment remain gated; P2.13 remains in progress.
