"""Offline NRAS claim retention tests using locally signed ES384 JWTs."""

import asyncio
import base64
import copy
import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from secretvm.verify.nvidia import (
    check_nvidia_gpu_attestation,
    check_nvidia_gpu_attestation_async,
)

FIXTURE = json.loads((Path(__file__).resolve().parents[2] / "test-data/nvidia_claims.json").read_text())
KEY = ec.generate_private_key(ec.SECP384R1())


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwt(claims):
    header = b64(json.dumps({"alg": "ES384", "kid": "test-key"}).encode())
    body = b64(json.dumps(claims).encode())
    data = f"{header}.{body}"
    r, s = utils.decode_dss_signature(KEY.sign(data.encode(), ec.ECDSA(hashes.SHA384())))
    return f"{data}.{b64(r.to_bytes(48, 'big') + s.to_bytes(48, 'big'))}"


def corrupt(token):
    header, body, signature = token.split(".")
    raw = bytearray(base64.urlsafe_b64decode(signature + "=="))
    raw[0] ^= 1
    return f"{header}.{body}.{b64(raw)}"


@pytest.fixture
def nras():
    numbers = KEY.public_key().public_numbers()
    jwk = {"kid": "test-key", "x": b64(numbers.x.to_bytes(48, "big")), "y": b64(numbers.y.to_bytes(48, "big"))}
    with patch("secretvm.verify.nvidia.requests.post") as post, patch("secretvm.verify.nvidia.requests.get") as get:
        get.return_value.json.return_value = {"keys": [jwk]}

        def configure(platform=None, gpus=None, tamper=""):
            platform = FIXTURE["platform"] if platform is None else platform
            gpus = {"GPU-0": FIXTURE["gpu"]} if gpus is None else gpus
            platform_token = jwt(platform)
            tokens = {gpu_id: jwt(claims) for gpu_id, claims in gpus.items()}
            if tamper == "platform":
                platform_token = corrupt(platform_token)
            elif tamper:
                tokens[tamper] = corrupt(tokens[tamper])
            post.return_value.status_code = 200
            post.return_value.json.return_value = [["JWT", platform_token], tokens]
            return post

        yield configure


def test_full_claims_preserve_nested_null_and_future_fields(nras):
    post = nras()
    result = check_nvidia_gpu_attestation('{"arch":"BLACKWELL","claims_version":"3.0"}')
    assert result.valid is True
    assert post.call_args.kwargs["json"]["claims_version"] == "4.0"
    assert post.call_args.kwargs["json"]["arch"] == "BLACKWELL"
    assert result.report["claims"] == FIXTURE["platform"]
    gpu = result.report["gpus"]["GPU-0"]
    assert gpu["claims"] == FIXTURE["gpu"]
    assert gpu["vbios_version"] == FIXTURE["gpu"]["x-nvidia-gpu-vbios-version"]
    assert gpu["driver_version"] == FIXTURE["gpu"]["x-nvidia-gpu-driver-version"]
    assert gpu["measurements"] == "success"
    assert gpu["claims"]["x-nvidia-attester-claims"]["FSP_UCODE_MIN_SVN"] == 5


@pytest.mark.parametrize("version", ["2.0", "3.0"])
def test_explicit_older_version_does_not_invent_opaque_data(nras, version):
    gpu = copy.deepcopy(FIXTURE["gpu"])
    for key in ["x-nvidia-attester-claims", "x-nvidia-mismatch-opaque-data-records", "x-nvidia-gpu-claims-version"]:
        del gpu[key]
    post = nras({**FIXTURE["platform"], "x-nvidia-ver": version}, {"GPU-0": gpu})
    result = check_nvidia_gpu_attestation("{}", claims_version=version)
    assert result.valid is True
    assert post.call_args.kwargs["json"]["claims_version"] == version
    assert "x-nvidia-attester-claims" not in result.report["gpus"]["GPU-0"]["claims"]


def test_multiple_gpus_keep_distinct_claims(nras):
    second = {**FIXTURE["gpu"], "ueid": "second-device"}
    nras(gpus={"GPU-0": FIXTURE["gpu"], "GPU-1": second})
    result = check_nvidia_gpu_attestation("{}")
    assert result.valid is True
    assert result.report["gpus"]["GPU-0"]["claims"] == FIXTURE["gpu"]
    assert result.report["gpus"]["GPU-1"]["claims"] == second


@pytest.mark.parametrize("target", ["platform", "GPU-0"])
def test_tampered_signatures_still_fail(nras, target):
    nras(tamper=target)
    result = check_nvidia_gpu_attestation("{}")
    assert result.valid is False
    key = "platform_jwt_signature" if target == "platform" else "GPU-0_jwt_signature"
    assert result.checks[key] is False


def test_opaque_mismatch_preserved_without_overriding_denial(nras):
    records = [{"id": 37, "name": "FSP_UCODE_MIN_SVN", "goldenType": "MIN_SVN", "goldenValue": 5, "runtimeType": "MIN_SVN", "runtimeValue": 4}]
    gpu = {**FIXTURE["gpu"], "measres": "fail", "x-nvidia-attester-claims": {"FSP_UCODE_MIN_SVN": 4}, "x-nvidia-mismatch-opaque-data-records": records}
    nras({**FIXTURE["platform"], "x-nvidia-overall-att-result": False}, {"GPU-0": gpu})
    result = check_nvidia_gpu_attestation("{}")
    assert result.valid is False
    assert result.report["gpus"]["GPU-0"]["claims"]["x-nvidia-mismatch-opaque-data-records"] == records


def test_unsupported_version_rejected_without_network(nras):
    post = nras()
    result = check_nvidia_gpu_attestation("{}", claims_version="5.0")
    assert result.valid is False
    assert "Unsupported NVIDIA claims version" in result.errors[0]
    post.assert_not_called()


def test_async_gpu_forwards_claims_version(nras):
    post = nras()
    result = asyncio.run(check_nvidia_gpu_attestation_async("{}", claims_version="3.0"))
    assert result.valid is True
    assert post.call_args.kwargs["json"]["claims_version"] == "3.0"


def test_vm_async_forwards_claims_version():
    from secretvm.verify.vm import check_secret_vm_async
    with patch("secretvm.verify.vm.check_secret_vm", return_value=Mock()) as check:
        asyncio.run(check_secret_vm_async("example.test", gpu_claims_version="3.0"))
    assert check.call_args.args[-1] == "3.0"
