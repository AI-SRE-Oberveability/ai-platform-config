"""Offline integrity, ownership and negative policy checks on real rendered inputs."""

import copy
import io
import json
import shutil
import subprocess
import sys
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import yaml
from fixtures import temporary_directory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import tools
import validate_config as config


class ConfigurationChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.objects = []
        config.verify_vendor()
        config.preflight_sources()
        binary = tools.executable()
        for environment in ["dev", "qa", "platform"]:
            result = subprocess.run(
                [str(binary), "build", str(config.ROOT / "environments" / environment)],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=60,
            )
            cls.objects.extend(config.load_yaml(result.stdout))

    def resource(self, kind, name=None):
        return copy.deepcopy(
            next(
                obj
                for obj in self.objects
                if obj["kind"] == kind
                and (name is None or obj["metadata"]["name"] == name)
            )
        )

    def test_actual_builds_satisfy_schema_scope_and_foundation_set(self):
        report = config.inspect_objects(self.objects)
        self.assertEqual(report["by_kind"]["Namespace"], 4)
        self.assertEqual(report["by_kind"]["CustomResourceDefinition"], 3)
        self.assertEqual(report["by_kind"]["Role"], 2)

    def test_no_workload_or_binding_objects_owned_by_configuration(self):
        self.assertFalse(
            {obj["kind"] for obj in self.objects}
            & {
                "ServiceAccount",
                "Deployment",
                "Secret",
                "RoleBinding",
                "ClusterRoleBinding",
            }
        )

    def test_duplicate_identity_rejected_across_api_versions(self):
        first = self.resource("Role")
        duplicate = copy.deepcopy(first)
        duplicate["apiVersion"] = "rbac.authorization.k8s.io/v1beta1"
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            config.inspect_objects([first, duplicate])

    def test_unknown_kind_or_api_is_not_silently_skipped(self):
        for kind in ["Secret", "ClusterRoleBinding", "ServiceAccount"]:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                config.inspect_objects([{"kind": kind, "apiVersion": "v1"}])
        obj = self.resource("Role")
        obj["apiVersion"] = "rbac.authorization.k8s.io/v1beta1"
        with self.assertRaises(ValueError):
            config.schema_check(obj)

    def test_core_schema_rejects_wrong_label_type(self):
        obj = self.resource("Namespace")
        obj["metadata"]["labels"] = ["invalid"]
        with self.assertRaisesRegex(ValueError, "schema"):
            config.schema_check(obj)

    def test_pod_security_and_namespace_boundaries_are_explicit(self):
        obj = self.resource("Namespace")
        obj["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] = "privileged"
        with self.assertRaises(ValueError):
            config.policy_check(obj)
        obj = self.resource("Role")
        obj["metadata"]["namespace"] = "kube-system"
        with self.assertRaises(ValueError):
            config.policy_check(obj)
        obj = self.resource("Namespace")
        obj["metadata"]["namespace"] = "ai-lab-dev"
        with self.assertRaises(ValueError):
            config.policy_check(obj)

    def test_rbac_denies_writes_wildcards_secrets_logs_and_nonresource_urls(self):
        for change in [
            {"verbs": ["*"]},
            {"verbs": ["create"]},
            {"resources": ["secrets"]},
            {"resources": ["pods/log"]},
            {"apiGroups": ["*"]},
            {"nonResourceURLs": ["*"]},
        ]:
            with self.subTest(change=change):
                obj = self.resource("Role")
                obj["rules"][0].update(change)
                with self.assertRaises(ValueError):
                    config.policy_check(obj)

    def test_network_rule_cannot_allow_world_or_all_namespaces(self):
        for peer in [
            {},
            {"ipBlock": {"cidr": "0.0.0.0/0"}},
            {"podSelector": {}},
            {"podSelector": {"matchLabels": {"app": "x"}}, "namespaceSelector": {}},
            {
                "podSelector": {"matchLabels": {"app": "x"}},
                "namespaceSelector": {
                    "matchLabels": {"kubernetes.io/metadata.name": "production"}
                },
            },
        ]:
            obj = self.resource("NetworkPolicy", "dns")
            obj["spec"]["egress"][0]["to"] = [peer]
            with self.subTest(peer=peer), self.assertRaises(ValueError):
                config.policy_check(obj)

    def test_network_allow_rule_requires_ports_and_known_port_set(self):
        for ports in [[], [{"port": 443}], [{"port": 53, "protocol": "SCTP"}]]:
            obj = self.resource("NetworkPolicy", "dns")
            obj["spec"]["egress"][0]["ports"] = ports
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                config.policy_check(obj)

    def test_default_deny_cannot_be_replaced_with_an_allow(self):
        values = copy.deepcopy(self.objects)
        next(
            obj
            for obj in values
            if obj["kind"] == "NetworkPolicy"
            and obj["metadata"]["name"] == "default-deny"
        )["spec"]["podSelector"] = {"matchLabels": {"unused": "value"}}
        with self.assertRaisesRegex(ValueError, "Default-deny"):
            config.inspect_objects(values)

    def test_crd_scope_or_storage_version_change_is_rejected(self):
        obj = self.resource("CustomResourceDefinition")
        obj["spec"]["scope"] = "Cluster"
        with self.assertRaises(ValueError):
            config.policy_check(obj)
        obj = self.resource("CustomResourceDefinition")
        obj["spec"]["versions"][0]["storage"] = False
        with self.assertRaises(ValueError):
            config.policy_check(obj)

    def test_rendered_crd_schema_cannot_bypass_the_upstream_lock(self):
        values = copy.deepcopy(self.objects)
        crd = next(obj for obj in values if obj["kind"] == "CustomResourceDefinition")
        crd["spec"]["names"]["categories"] = ["altered-through-an-authored-input"]
        with self.assertRaisesRegex(ValueError, "Rendered CRD differs"):
            config.inspect_objects(values)

    def test_yaml_duplicate_keys_nonobjects_and_unsafe_tags_rejected(self):
        for text in [
            "kind: Role\nkind: Secret\n",
            "- item\n",
            "!!python/object:builtins.object {}",
        ]:
            with (
                self.subTest(text=text),
                self.assertRaises((ValueError, yaml.YAMLError)),
            ):
                config.load_yaml(text)

    def test_remote_and_escaping_kustomize_inputs_fail_before_build(self):
        for resource in [
            "https://example.invalid/source.yaml",
            "../outside.yaml",
            ".git/config",
        ]:
            with temporary_directory() as folder:
                root = Path(folder)
                (root / "kustomization.yaml").write_text(
                    yaml.safe_dump(
                        {
                            "apiVersion": "kustomize.config.k8s.io/v1beta1",
                            "kind": "Kustomization",
                            "resources": [resource],
                        }
                    )
                )
                with self.subTest(resource=resource), self.assertRaises(ValueError):
                    config.preflight_sources(root)

    def test_unsupported_kustomize_generators_cannot_fetch_or_emit_secrets(self):
        with temporary_directory() as folder:
            root = Path(folder)
            (root / "kustomization.yaml").write_text(
                yaml.safe_dump(
                    {
                        "apiVersion": "kustomize.config.k8s.io/v1beta1",
                        "kind": "Kustomization",
                        "secretGenerator": [{"name": "secret"}],
                    }
                )
            )
            with self.assertRaises(ValueError):
                config.preflight_sources(root)

    def test_vendor_tamper_missing_or_unlisted_input_is_rejected(self):
        for change in ["tamper", "missing", "unlisted"]:
            with temporary_directory() as folder:
                root = Path(folder)
                shutil.copytree(config.ROOT / "vendor", root / "vendor")
                file = root / "vendor/kubernetes/v1.35.0/namespace.json"
                if change == "tamper":
                    file.write_text("{}")
                elif change == "missing":
                    file.unlink()
                else:
                    (root / "vendor/unlisted.yaml").write_text("kind: Secret\n")
                with self.subTest(change=change), self.assertRaises(ValueError):
                    config.verify_vendor(root)


class ToolChecks(unittest.TestCase):
    def test_caches_inside_any_git_checkout_are_rejected(self):
        with temporary_directory() as folder:
            root = Path(folder)
            (root / ".git").mkdir()
            with self.assertRaises(ValueError):
                tools.private_cache(root / "unusual/cache")
        with self.assertRaises(ValueError):
            tools.private_cache(config.ROOT / ".runtime")

    def test_checksum_verified_archive_member_only(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("kustomize.exe", b"fixture binary")
            archive.writestr("../escape", b"not extracted")
        data = buffer.getvalue()
        self.assertEqual(
            tools.unpack(
                data,
                "kustomize.exe",
                tools.digest(data),
                tools.digest(b"fixture binary"),
                True,
            ),
            b"fixture binary",
        )
        for archive_hash, binary_hash in [
            ("0" * 64, tools.digest(b"fixture binary")),
            (tools.digest(data), "0" * 64),
        ]:
            with self.assertRaises(ValueError):
                tools.unpack(data, "kustomize.exe", archive_hash, binary_hash, True)

    def test_download_target_cannot_change_host_or_member(self):
        with temporary_directory() as folder:
            root = Path(folder)
            (root / "locks").mkdir()
            source = json.loads((config.ROOT / "locks/toolchain.json").read_text())
            for change in ["url", "member"]:
                value = copy.deepcopy(source)
                value["tools"]["kustomize"]["platforms"]["windows_amd64"][change] = (
                    "https://example.invalid/file" if change == "url" else "../escape"
                )
                (root / "locks/toolchain.json").write_text(json.dumps(value))
                with (
                    patch.object(tools.platform, "system", return_value="Windows"),
                    patch.object(tools.platform, "machine", return_value="AMD64"),
                    self.assertRaises(ValueError),
                ):
                    tools.selected(root)

    def test_schema_network_retrieval_is_forbidden(self):
        with self.assertRaises(ValueError):
            config.no_remote_schema("https://example.invalid/schema")
