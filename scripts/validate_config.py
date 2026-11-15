"""Build and validate owned config offline; never contact a Kubernetes API."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections import Counter
from pathlib import Path

import jsonschema
import yaml
from referencing import Registry
from tools import DEFAULT_CACHE, executable

ROOT = Path(__file__).resolve().parents[1]
APIS = {
    "Namespace": ("v1", "namespace.json", False),
    "ResourceQuota": ("v1", "resourcequota.json", True),
    "LimitRange": ("v1", "limitrange.json", True),
    "Role": ("rbac.authorization.k8s.io/v1", "role-rbac-v1.json", True),
    "NetworkPolicy": ("networking.k8s.io/v1", "networkpolicy-networking-v1.json", True),
    "CustomResourceDefinition": (
        "apiextensions.k8s.io/v1",
        "apiextensions-v1-openapi.json",
        False,
    ),
}
NAMESPACES = {"ai-lab-dev", "ai-lab-qa", "ai-observability", "argocd"}
CRDS = {
    "applications.argoproj.io",
    "applicationsets.argoproj.io",
    "appprojects.argoproj.io",
}


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    result = {}
    for key, value in node.value:
        key = loader.construct_object(key, deep=deep)
        if key in result:
            raise ValueError("Duplicate YAML mapping key")
        result[key] = loader.construct_object(value, deep=deep)
    return result


UniqueLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping
)


def load_yaml(text):
    values = list(yaml.load_all(text, Loader=UniqueLoader))
    if any(value is not None and not isinstance(value, dict) for value in values):
        raise ValueError("YAML documents must be objects")
    return [value for value in values if value is not None]


def owned(root, relative):
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()) or set(
        path.relative_to(root.resolve()).parts
    ) & {".git", ".runtime", ".venv"}:
        raise ValueError("Source path leaves its repository")
    return path


def verify_vendor(root=ROOT):
    lock = json.loads((root / "vendor/manifest-lock.json").read_text(encoding="utf-8"))
    if lock.get("schema_version") != 1 or not lock.get("artifacts"):
        raise ValueError("Vendor lock is required")
    seen = set()
    for row in lock["artifacts"]:
        name = row["path"]
        if (
            name in seen
            or not name.startswith("vendor/")
            or not re.fullmatch("[0-9a-f]{40}", row["commit"])
            or row["commit"] == "0" * 40
        ):
            raise ValueError("Vendor identity/commit is invalid")
        seen.add(name)
        path = owned(root, name)
        if (
            not path.is_file()
            or hashlib.sha256(path.read_bytes()).hexdigest() != row["sha256"]
        ):
            raise ValueError("Vendored input missing or checksum mismatch")
        if row["commit"] not in row["url"] or not row["url"].startswith(
            ("https://raw.githubusercontent.com/", "https://github.com/")
        ):
            raise ValueError("Vendor source must use an immutable reviewed commit")
    actual = {
        path.relative_to(root).as_posix()
        for path in (root / "vendor").rglob("*")
        if path.is_file()
        and path.name not in {"manifest-lock.json", "kustomization.yaml", "README.md"}
    }
    if actual != seen:
        raise ValueError("Unlisted vendored input")
    return lock


def preflight_sources(root=ROOT):
    allowed = {"apiVersion", "kind", "resources", "namespace", "labels"}
    for path in root.rglob("kustomization.yaml"):
        if ".git" in path.parts:
            continue
        documents = load_yaml(path.read_text(encoding="utf-8"))
        if len(documents) != 1 or set(documents[0]) - allowed:
            raise ValueError(
                "Unsupported Kustomize feature; only offline reviewed resources allowed"
            )
        obj = documents[0]
        if (
            obj.get("apiVersion") != "kustomize.config.k8s.io/v1beta1"
            or obj.get("kind") != "Kustomization"
        ):
            raise ValueError("Kustomization schema is invalid")
        for resource in obj.get("resources", []):
            if (
                not isinstance(resource, str)
                or ":" in resource
                or resource.startswith(("/", "\\"))
            ):
                raise ValueError("Remote/absolute Kustomize input forbidden")
            target = owned(root, (path.parent / resource).relative_to(root))
            if not target.exists():
                raise ValueError("Missing Kustomize input")


def no_remote_schema(uri):
    raise ValueError("Remote schema retrieval forbidden")


def schema_check(obj, root=ROOT):
    kind = obj.get("kind")
    if kind not in APIS or obj.get("apiVersion") != APIS[kind][0]:
        raise ValueError("Unknown resource schema/scope or API version")
    schema = json.loads(
        (root / "vendor/kubernetes/v1.35.0" / APIS[kind][1]).read_text(encoding="utf-8")
    )
    if kind == "CustomResourceDefinition":
        schema = {
            "$schema": "http://json-schema.org/draft-04/schema#",
            "$ref": "#/components/schemas/io.k8s.apiextensions-apiserver.pkg.apis.apiextensions.v1.CustomResourceDefinition",
            "components": schema["components"],
        }
    if schema.get("$schema") not in {
        "http://json-schema.org/schema#",
        "http://json-schema.org/draft-04/schema#",
    }:
        raise ValueError("Unreviewed schema dialect")
    # The locked swagger-derived schema# inputs use Draft 4 keywords. Select the
    # dialect explicitly instead of silently falling back to the latest version.
    errors = list(
        jsonschema.Draft4Validator(
            schema, registry=Registry(retrieve=no_remote_schema)
        ).iter_errors(obj)
    )
    if errors:
        raise ValueError("Offline Kubernetes schema validation failed")


def policy_check(obj):
    kind = obj["kind"]
    meta = obj.get("metadata", {})
    if not isinstance(meta.get("name"), str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9.-]{0,252}", meta["name"]
    ):
        raise ValueError("Resource name required")
    namespace = meta.get("namespace", "")
    if APIS[kind][2] and namespace not in NAMESPACES:
        raise ValueError("Resource namespace outside the approved slice")
    if not APIS[kind][2] and namespace:
        raise ValueError("Cluster-scoped resource cannot have a namespace")
    if kind == "Namespace":
        labels = meta.get("labels", {})
        if (
            meta["name"] not in NAMESPACES
            or labels.get("pod-security.kubernetes.io/enforce") != "restricted"
            or labels.get("pod-security.kubernetes.io/enforce-version") != "v1.35"
        ):
            raise ValueError("Namespace/pod-security contract violated")
    elif kind == "Role":
        if not obj.get("rules"):
            raise ValueError("Reviewed read-only rules required")
        for rule in obj.get("rules", []):
            if set(rule) - {"apiGroups", "resources", "verbs"}:
                raise ValueError("Unexpected RBAC rule capability")
            if not rule.get("verbs") or set(rule["verbs"]) - {"get", "list"}:
                raise ValueError("RBAC must remain bounded read-only")
            groups = set(rule.get("apiGroups", []))
            resources = set(rule.get("resources", []))
            allowed = (
                {"pods", "services", "events"}
                if groups == {""}
                else {"deployments", "replicasets"}
                if groups == {"apps"}
                else set()
            )
            if not resources or resources - allowed:
                raise ValueError("RBAC resource/group outside the allowlist")
    elif kind == "NetworkPolicy":
        for direction, peers in [("ingress", "from"), ("egress", "to")]:
            for rule in obj["spec"].get(direction, []):
                if not rule.get(peers) or not rule.get("ports"):
                    raise ValueError(
                        "Network allow rule must constrain peers and ports"
                    )
                for peer in rule[peers]:
                    if "ipBlock" in peer or not peer.get("podSelector", {}).get(
                        "matchLabels"
                    ):
                        raise ValueError(
                            "Unbounded or IP-based peer forbidden before target approval"
                        )
                    if "namespaceSelector" in peer and not peer[
                        "namespaceSelector"
                    ].get("matchLabels"):
                        raise ValueError("Wildcard namespace peer forbidden")
                    if "namespaceSelector" in peer and peer[
                        "namespaceSelector"
                    ] not in [
                        {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                        {
                            "matchLabels": {
                                "kubernetes.io/metadata.name": "ai-observability"
                            }
                        },
                        {"matchLabels": {"ai-lab.example/workload": "true"}},
                    ]:
                        raise ValueError("Namespace peer outside the approved slice")
                for port in rule["ports"]:
                    if port.get("port") not in {53, 8080, 4317, 4318} or port.get(
                        "protocol", "TCP"
                    ) not in {"TCP", "UDP"}:
                        raise ValueError("Unapproved network port/protocol")
    elif kind == "CustomResourceDefinition":
        spec = obj["spec"]
        if (
            meta["name"] not in CRDS
            or spec.get("group") != "argoproj.io"
            or spec.get("scope") != "Namespaced"
        ):
            raise ValueError("CRD identity/scope outside reviewed Argo inputs")
        if sum(version.get("storage") is True for version in spec["versions"]) != 1:
            raise ValueError("CRD must have exactly one storage version")


def inspect_objects(objects, root=ROOT):
    seen = set()
    for obj in objects:
        kind = obj.get("kind")
        if kind not in APIS:
            raise ValueError("Resource is outside configuration ownership")
        api = obj.get("apiVersion", "")
        group = api.split("/")[0] if "/" in api else ""
        meta = obj.get("metadata", {})
        identity = (group, kind, meta.get("namespace", ""), meta.get("name", ""))
        if identity in seen:
            raise ValueError("Duplicate resource identity, independent of API version")
        seen.add(identity)
    vendor_lock = json.loads(
        (root / "vendor/manifest-lock.json").read_text(encoding="utf-8")
    )
    original_crds = {}
    for row in vendor_lock["artifacts"]:
        if row["kind"] == "crd":
            documents = load_yaml(owned(root, row["path"]).read_text(encoding="utf-8"))
            if (
                len(documents) != 1
                or documents[0].get("kind") != "CustomResourceDefinition"
            ):
                raise ValueError("Locked CRD source is not a single CRD")
            original_crds[documents[0]["metadata"]["name"]] = documents[0]
    for obj in objects:
        if obj.get("kind") == "CustomResourceDefinition" and obj != original_crds.get(
            obj.get("metadata", {}).get("name")
        ):
            raise ValueError("Rendered CRD differs from its locked upstream object")
        schema_check(obj, root)
        policy_check(obj)
    namespaces = {
        obj["metadata"]["name"] for obj in objects if obj["kind"] == "Namespace"
    }
    crds = {
        obj["metadata"]["name"]
        for obj in objects
        if obj["kind"] == "CustomResourceDefinition"
    }
    if namespaces != NAMESPACES or crds != CRDS:
        raise ValueError("Expected namespace/CRD foundation set missing or expanded")
    for namespace in ["ai-lab-dev", "ai-lab-qa", "ai-observability"]:
        deny = [
            obj
            for obj in objects
            if obj["kind"] == "NetworkPolicy"
            and obj["metadata"].get("namespace") == namespace
            and obj["metadata"]["name"] == "default-deny"
        ]
        if (
            len(deny) != 1
            or deny[0]["spec"].get("podSelector") != {}
            or set(deny[0]["spec"].get("policyTypes", [])) != {"Ingress", "Egress"}
            or deny[0]["spec"].get("ingress")
            or deny[0]["spec"].get("egress")
        ):
            raise ValueError("Default-deny foundation missing or weakened")
    return {
        "objects": len(objects),
        "by_kind": dict(Counter(obj["kind"] for obj in objects)),
        "identities": sorted([list(key) for key in seen]),
    }


def validate(root=ROOT, cache=DEFAULT_CACHE):
    lock = verify_vendor(root)
    preflight_sources(root)
    binary = executable(cache, root)
    objects = []
    render_hashes = {}
    for environment in ["dev", "qa", "platform"]:
        result = subprocess.run(
            [str(binary), "build", str(root / "environments" / environment)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
        )
        if result.returncode:
            raise ValueError("Kustomize build failed; no cluster operation attempted")
        objects.extend(load_yaml(result.stdout))
        render_hashes[environment] = hashlib.sha256(result.stdout.encode()).hexdigest()
    return {
        "schema_version": 1,
        "status": "passed_offline_configuration_checks",
        "kustomize_version": json.loads((root / "locks/toolchain.json").read_text())[
            "tools"
        ]["kustomize"]["version"],
        "vendor_artifacts_verified": len(lock["artifacts"]),
        "render_hashes": render_hashes,
        **inspect_objects(objects, root),
        "deployable": False,
        "azure_deployment_enabled": False,
        "cluster_operations": False,
        "limitations": [
            "Schema/source-policy checks do not execute API-server admission/CEL or prove live NetworkPolicy/pod-security enforcement.",
            "Argo controller connectivity, workload/chart labels, identity delivery and APIM egress remain later integration work; no deployment is approved.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = validate(cache=args.cache)
    except (
        ValueError,
        KeyError,
        OSError,
        yaml.YAMLError,
        subprocess.TimeoutExpired,
    ) as error:
        raise SystemExit(
            "Configuration validation failed: " + type(error).__name__
        ) from None
    if args.output:
        args.output.write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
