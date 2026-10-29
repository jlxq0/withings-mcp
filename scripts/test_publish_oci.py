#!/usr/bin/env python3
"""Exercise publish_oci.sh against a disposable localhost registry.

Requires docker and regctl on PATH, plus an attested OCI layout from a build.
No production registry write is made. The fixture must include SPDX and SLSA.
Run: python3 scripts/test_publish_oci.py --layout /path/to/oci --digest sha256:...
"""

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import urllib.request
import urllib.error

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--layout", required=True)
parser.add_argument("--digest", required=True)
args = parser.parse_args()
layout = str(pathlib.Path(args.layout).resolve())
digest = args.digest
reg = shutil.which("regctl")
assert reg, "regctl must be on PATH"
assert (
    hashlib.sha256(pathlib.Path(reg).read_bytes()).hexdigest()
    == "3737fbbdd791e04e7a831640b681f3397a376498e80e2ad9b1b2d27296f239bc"
), "use the CI-pinned regctl binary"
helper = str(pathlib.Path(__file__).with_name("publish_oci.sh"))
private = tempfile.TemporaryDirectory(prefix="oci-publish-test-")
out = pathlib.Path(private.name)
env = os.environ | {"REGCTL_CONFIG": str(out / "regctl-config.json")}
cid = subprocess.check_output(
    [
        "docker",
        "run",
        "-d",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/var/lib/registry:rw,size=128m",
        "-e",
        "REGISTRY_STORAGE_DELETE_ENABLED=true",
        "-p",
        "127.0.0.1::5000",
        "registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373",
    ],
    text=True,
).strip()


def run(args, ok=True):
    p = subprocess.run(args, text=True, capture_output=True, env=env)
    if ok and p.returncode:
        raise RuntimeError(p.stderr)
    return p


try:
    info = json.loads(subprocess.check_output(["docker", "inspect", cid]))[0]
    port = info["NetworkSettings"]["Ports"]["5000/tcp"][0]["HostPort"]
    host = "localhost:" + port
    repo = host + "/test/image"
    run([str(reg), "registry", "set", host, "--tls", "disabled"])
    # The helper requires an existing repository. Seed it with a tiny unrelated
    # image, never the target index whose recursive copy is under test.
    seed = out / "seed"
    (seed / "blobs/sha256").mkdir(parents=True)
    (seed / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')

    def seed_blob(value, media_type):
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        value_digest = "sha256:" + hashlib.sha256(body).hexdigest()
        (seed / "blobs/sha256" / value_digest.split(":")[1]).write_bytes(body)
        return {"mediaType": media_type, "digest": value_digest, "size": len(body)}

    config = seed_blob(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {"Env": ["FIXTURE=unrelated"]},
            "rootfs": {"type": "layers", "diff_ids": []},
            "history": [],
        },
        "application/vnd.oci.image.config.v1+json",
    )
    manifest = seed_blob(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": config,
            "layers": [],
        },
        "application/vnd.oci.image.manifest.v1+json",
    )
    (seed / "index.json").write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "manifests": [
                    {
                        **manifest,
                        "annotations": {"org.opencontainers.image.ref.name": "seed"},
                    }
                ],
            }
        )
    )

    def seed_repo(destination):
        run(
            [
                str(reg),
                "image",
                "copy",
                "--force-recursive",
                "ocidir://" + str(seed) + ":seed",
                destination + ":seed",
            ]
        )

    objects, types, layer_digests = {}, [], []

    def collect(value_digest, kind):
        if value_digest in objects:
            return
        local = pathlib.Path(
            layout, "blobs", "sha256", value_digest.split(":")[1]
        ).read_bytes()
        assert hashlib.sha256(local).hexdigest() == value_digest.split(":")[1]
        objects[value_digest] = (kind, local)
        if kind == "manifests":
            value = json.loads(local)
            for item in value.get("manifests", []):
                collect(item["digest"], "manifests")
            if "config" in value:
                collect(value["config"]["digest"], "blobs")
            for item in value.get("layers", []):
                collect(item["digest"], "blobs")
                layer_digests.append(item["digest"])
                if item.get("annotations", {}).get("in-toto.io/predicate-type"):
                    types.append(item["annotations"]["in-toto.io/predicate-type"])

    def remote_object(repository, value_digest, kind):
        request = urllib.request.Request(
            "http://"
            + repository.split("/", 1)[0]
            + "/v2/"
            + repository.split("/", 1)[1]
            + "/"
            + kind
            + "/"
            + value_digest,
            headers={
                "Accept": "application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json"
            },
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.read()

    def assert_target_absent(repository):
        for value_digest, (kind, _local) in objects.items():
            try:
                remote_object(repository, value_digest, kind)
            except urllib.error.HTTPError as error:
                assert error.code == 404, error.code
            else:
                raise AssertionError("target object prepopulated: " + value_digest)

    collect(digest, "manifests")
    assert any("spdx" in x for x in types) and any("slsa" in x for x in types)
    assert manifest["digest"] not in objects and config["digest"] not in objects
    seed_repo(repo)
    assert_target_absent(repo)
    first = run(["bash", helper, layout, digest, repo, "v0.0.1"])
    assert "Published scanned OCI" in first.stdout
    replay = run(["bash", helper, layout, digest, repo, "v0.0.1"])
    # Every target object was absent before the actual publisher invocation.
    for value_digest, (kind, local) in objects.items():
        remote = remote_object(repo, value_digest, kind)
        assert (
            remote == local
            and hashlib.sha256(remote).hexdigest() == value_digest.split(":")[1]
        )
    # Existing different release tag must fail before changing release/latest.
    index = json.loads(
        pathlib.Path(layout, "blobs", "sha256", digest.split(":")[1]).read_text()
    )
    other = index["manifests"][0]["digest"]
    run([str(reg), "image", "copy", repo + "@" + other, repo + ":v0.0.2"])
    conflict = run(["bash", helper, layout, digest, repo, "v0.0.2"], False)
    assert conflict.returncode
    assert run([str(reg), "image", "digest", repo + ":v0.0.2"]).stdout.strip() == other
    assert run([str(reg), "image", "digest", repo + ":latest"]).stdout.strip() == digest
    invalid = run(["bash", helper, layout, "sha256:" + "0" * 64, repo, "v0.0.3"], False)
    assert invalid.returncode
    assert "v0.0.3" not in run([str(reg), "tag", "ls", repo]).stdout.splitlines()
    # A valid root with a missing descendant must also refuse before exposing
    # a release/latest tag in a distinct repository with no target objects.
    broken = out / "missing-descendant"
    shutil.copytree(layout, broken)
    missing_digest = layer_digests[-1]
    (broken / "blobs/sha256" / missing_digest.split(":")[1]).unlink()
    missing_repo = host + "/test/missing"
    seed_repo(missing_repo)
    assert_target_absent(missing_repo)
    incomplete = run(
        ["bash", helper, str(broken), digest, missing_repo, "v0.0.4"], False
    )
    assert incomplete.returncode
    assert run([str(reg), "tag", "ls", missing_repo]).stdout.splitlines() == ["seed"]
    result = {
        "tool": "regctl v0.11.7",
        "binary_sha256": "3737fbbdd791e04e7a831640b681f3397a376498e80e2ad9b1b2d27296f239bc",
        "exact_index_digest": digest,
        "verified_objects": len(objects),
        "initially_absent_objects": len(objects),
        "attestation_types": types,
        "checks": {
            "initial_publish": True,
            "same_digest_replay": True,
            "existing_different_tag_refused": True,
            "missing_root_digest_refused_without_tag": True,
            "valid_root_missing_descendant_refused_without_release_tags": True,
            "unrelated_seed_does_not_prepopulate_target": True,
            "byte_identical_recursive_index_blobs": True,
        },
        "scope": "temporary localhost registry; no production publication",
    }
    print(json.dumps(result))
finally:
    subprocess.run(["docker", "stop", cid], stdout=subprocess.DEVNULL, check=True)
    private.cleanup()
