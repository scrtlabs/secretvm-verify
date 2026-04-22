"""
Tests for secretvm.verify library.

These are integration tests that use the real attestation quote files
and contact real verification services (Intel PCS, AMD KDS, NVIDIA NRAS).
They require network access.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from secretvm.verify import (
    AttestationResult,
    check_sev_cpu_attestation,
    check_cpu_attestation,
    check_nvidia_gpu_attestation,
    check_secret_vm,
    check_tdx_cpu_attestation,
    resolve_secretvm_version,
    verify_tdx_workload,
    verify_sev_workload,
    verify_workload,
    format_workload_result,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "test-data"


@pytest.fixture
def tdx_quote():
    return (FIXTURES_DIR / "cpu_quote.txt").read_text()


@pytest.fixture
def amd_quote():
    return (FIXTURES_DIR / "amd_cpu_quote.txt").read_text()


@pytest.fixture
def gpu_attestation():
    return (FIXTURES_DIR / "gpu_attest.txt").read_text()


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

class TestAttestationResult:
    def test_fields(self):
        r = AttestationResult(valid=True, attestation_type="TEST")
        assert r.valid is True
        assert r.attestation_type == "TEST"
        assert r.checks == {}
        assert r.report == {}
        assert r.errors == []

    def test_failed_result(self):
        r = AttestationResult(
            valid=False, attestation_type="TEST",
            errors=["something broke"],
        )
        assert r.valid is False
        assert len(r.errors) == 1


# ---------------------------------------------------------------------------
# Intel TDX
# ---------------------------------------------------------------------------

class TestTdxAttestation:
    def test_valid_quote(self, tdx_quote):
        result = check_tdx_cpu_attestation(tdx_quote)
        assert isinstance(result, AttestationResult)
        assert result.attestation_type == "TDX"
        assert result.valid is True
        assert result.checks["quote_parsed"] is True
        assert result.checks["quote_verified"] is True
        assert result.errors == []

    def test_report_fields(self, tdx_quote):
        result = check_tdx_cpu_attestation(tdx_quote)
        report = result.report
        assert report["version"] == 4
        assert report["tee_type"] == 0x81
        assert len(report["mr_td"]) == 96  # 48 bytes as hex
        assert len(report["report_data"]) == 128  # 64 bytes as hex
        assert report["fmspc"] != ""
        assert "UpToDate" in report["tcb_status"] or "OutOfDate" in report["tcb_status"]

    def test_invalid_hex(self):
        result = check_tdx_cpu_attestation("not-valid-hex!!!")
        assert result.valid is False
        assert result.checks["quote_parsed"] is False
        assert len(result.errors) > 0

    def test_truncated_quote(self):
        result = check_tdx_cpu_attestation("aa" * 100)  # 100 bytes, too short
        assert result.valid is False
        assert result.checks["quote_parsed"] is False

    def test_empty_input(self):
        result = check_tdx_cpu_attestation("")
        assert result.valid is False

    def test_corrupted_signature(self, tdx_quote):
        """Flip a byte in the signature area to break the quote signature."""
        raw = bytes.fromhex(tdx_quote.strip())
        # Signature data starts at offset 636 (632 + 4 byte length)
        corrupted = bytearray(raw)
        corrupted[640] ^= 0xFF
        result = check_tdx_cpu_attestation(corrupted.hex())
        assert result.checks["quote_verified"] is False
        assert result.valid is False


# ---------------------------------------------------------------------------
# AMD SEV-SNP
# ---------------------------------------------------------------------------

class TestAmdAttestation:
    def test_valid_report(self, amd_quote):
        result = check_sev_cpu_attestation(amd_quote, product="Genoa")
        assert isinstance(result, AttestationResult)
        assert result.attestation_type == "SEV-SNP"
        assert result.valid is True
        assert result.checks["report_parsed"] is True
        assert result.checks["vcek_fetched"] is True
        assert result.checks["cert_chain_valid"] is True
        assert result.checks["report_signature_valid"] is True
        assert result.errors == []

    def test_report_fields(self, amd_quote):
        result = check_sev_cpu_attestation(amd_quote, product="Genoa")
        if result.checks.get("vcek_fetched") is False and "429" in str(result.errors):
            pytest.skip("AMD KDS rate-limited")
        report = result.report
        assert report["version"] == 3
        assert report["vmpl"] == 1
        assert report["product"] == "Genoa"
        assert report["debug_allowed"] is False
        assert len(report["measurement"]) == 96  # 48 bytes as hex
        assert len(report["report_data"]) == 128  # 64 bytes as hex
        assert len(report["chip_id"]) == 128  # 64 bytes as hex

    def test_auto_detect_product(self, amd_quote):
        result = check_sev_cpu_attestation(amd_quote)
        if result.checks.get("vcek_fetched") is False and "429" in str(result.errors):
            pytest.skip("AMD KDS rate-limited")
        assert result.valid is True
        assert result.report["product"] == "Genoa"

    def test_invalid_base64(self):
        result = check_sev_cpu_attestation("!!!not-base64!!!")
        assert result.valid is False
        assert result.checks["report_parsed"] is False
        assert len(result.errors) > 0

    def test_truncated_report(self):
        import base64
        short = base64.b64encode(b"\x00" * 100).decode()
        result = check_sev_cpu_attestation(short)
        assert result.valid is False
        assert result.checks["report_parsed"] is False

    def test_empty_input(self):
        result = check_sev_cpu_attestation("")
        assert result.valid is False

    def test_wrong_product(self, amd_quote):
        result = check_sev_cpu_attestation(amd_quote, product="Milan")
        assert result.valid is False
        assert result.checks.get("vcek_fetched") is False

    def test_corrupted_signature(self, amd_quote):
        """Flip a byte in the report body to break the signature."""
        import base64
        raw = base64.b64decode(amd_quote.strip())
        corrupted = bytearray(raw)
        corrupted[0x090] ^= 0xFF  # corrupt the measurement field
        data = base64.b64encode(corrupted).decode()
        result = check_sev_cpu_attestation(data, product="Genoa")
        if result.checks.get("vcek_fetched") is False and "429" in str(result.errors):
            pytest.skip("AMD KDS rate-limited")
        assert result.checks["report_signature_valid"] is False


# ---------------------------------------------------------------------------
# CPU auto-detect (TDX vs SEV-SNP)
# ---------------------------------------------------------------------------

class TestCpuAttestation:
    def test_detects_tdx(self, tdx_quote):
        result = check_cpu_attestation(tdx_quote)
        assert result.attestation_type == "TDX"
        assert result.valid is True

    def test_detects_amd(self, amd_quote):
        result = check_cpu_attestation(amd_quote, product="Genoa")
        assert result.attestation_type == "SEV-SNP"
        if result.checks.get("vcek_fetched") is False and "429" in str(result.errors):
            pytest.skip("AMD KDS rate-limited")
        assert result.valid is True

    def test_unknown_input(self):
        result = check_cpu_attestation("this is not a quote")
        assert result.valid is False
        assert result.attestation_type == "unknown"
        assert len(result.errors) > 0

    def test_empty_input(self):
        result = check_cpu_attestation("")
        assert result.valid is False


# ---------------------------------------------------------------------------
# NVIDIA GPU
# ---------------------------------------------------------------------------

class TestNvidiaAttestation:
    def test_valid_attestation(self, gpu_attestation):
        result = check_nvidia_gpu_attestation(gpu_attestation)
        assert isinstance(result, AttestationResult)
        assert result.attestation_type == "NVIDIA-GPU"
        assert result.valid is True
        assert result.checks["input_parsed"] is True
        assert result.checks["nras_submission"] is True
        assert result.checks["platform_jwt_signature"] is True
        assert result.errors == []

    def test_report_fields(self, gpu_attestation):
        result = check_nvidia_gpu_attestation(gpu_attestation)
        report = result.report
        assert report["overall_result"] is True
        assert "gpus" in report
        assert len(report["gpus"]) > 0
        gpu = list(report["gpus"].values())[0]
        assert gpu["model"] is not None
        assert gpu["attestation_report_signature_verified"] is True

    def test_invalid_json(self):
        result = check_nvidia_gpu_attestation("{not valid json")
        assert result.valid is False
        assert result.checks["input_parsed"] is False
        assert len(result.errors) > 0

    def test_empty_json(self):
        result = check_nvidia_gpu_attestation("{}")
        assert result.valid is False
        assert result.checks.get("nras_submission") is False

    def test_empty_input(self):
        result = check_nvidia_gpu_attestation("")
        assert result.valid is False


# ---------------------------------------------------------------------------
# Secret VM (end-to-end)
# ---------------------------------------------------------------------------

_M = "secretvm.verify"

# Helpers to build mock HTTP responses
def _mock_response(text, status_code=200, content_type="text/plain"):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    resp.headers = {"content-type": content_type}
    resp.raise_for_status = MagicMock()
    if content_type.startswith("application/json"):
        resp.json.return_value = json.loads(text)
    else:
        resp.json.return_value = json.loads(text) if text.strip().startswith("{") else None
    return resp


def _make_test_data(tls_hex="aa" * 32, nonce_hex="bb" * 32):
    """Build consistent test data for check_secret_vm tests."""
    from secretvm.verify import WorkloadResult

    report_data = tls_hex + nonce_hex
    tls_fp = bytes.fromhex(tls_hex)

    cpu_result = AttestationResult(
        valid=True, attestation_type="TDX",
        checks={"quote_parsed": True, "quote_verified": True},
        report={"report_data": report_data, "mr_td": "cc" * 48},
    )
    gpu_result = AttestationResult(
        valid=True, attestation_type="NVIDIA-GPU",
        checks={"platform_jwt_signature": True},
        report={"overall_result": True, "gpus": {}},
    )
    gpu_json = json.dumps({"nonce": nonce_hex, "arch": "HOPPER", "evidence_list": []})
    no_gpu_json = json.dumps({
        "error": "GPU attestation not available",
        "details": "The GPU attestation data has not been generated or is not ready yet",
    })
    workload_pass = WorkloadResult(
        status="authentic_match", template_name="small",
        artifacts_ver="v0.0.25", env="prod",
    )
    poc_pass = AttestationResult(
        valid=True, attestation_type="PROOF-OF-CLOUD",
        checks={"proof_of_cloud_verified": True},
        report={"proof_of_cloud": {"origin": "scrt", "proof_of_cloud": True}},
    )

    return tls_fp, cpu_result, gpu_result, gpu_json, no_gpu_json, workload_pass, poc_pass


class TestSecretVm:
    def test_unreachable_host(self):
        result = check_secret_vm("https://192.0.2.1:29343")
        assert result.valid is False
        assert result.attestation_type == "SECRET-VM"
        assert result.checks.get("tls_cert_fetched") is False
        assert len(result.errors) > 0

    def test_invalid_url(self):
        result = check_secret_vm("")
        assert result.valid is False

    def test_url_parsing(self):
        from secretvm.verify.vm import _parse_vm_url

        assert _parse_vm_url("myhost") == ("myhost", 29343)
        assert _parse_vm_url("myhost:1234") == ("myhost", 1234)
        assert _parse_vm_url("https://myhost:5555") == ("myhost", 5555)
        assert _parse_vm_url("https://myhost") == ("myhost", 29343)

    def test_vm_with_gpu_all_pass(self):
        tls_fp, cpu_result, gpu_result, gpu_json, _, workload_pass, poc_pass = _make_test_data()

        with patch(f"{_M}._get_tls_cert_fingerprint", return_value=tls_fp), \
             patch(f"{_M}.check_cpu_attestation", return_value=cpu_result), \
             patch(f"{_M}.check_nvidia_gpu_attestation", return_value=gpu_result), \
             patch(f"{_M}.verify_workload", return_value=workload_pass), \
             patch(f"{_M}.check_proof_of_cloud", return_value=poc_pass), \
             patch(f"{_M}.requests") as mock_req:
            mock_req.get.side_effect = [
                _mock_response("fake_cpu_quote"),
                _mock_response(gpu_json, content_type="application/json"),
                _mock_response("version: '3'\nservices: {}"),
            ]
            result = check_secret_vm("https://test-vm:29343")

        assert result.valid is True
        assert result.attestation_type == "SECRET-VM"
        assert result.checks["tls_cert_fetched"] is True
        assert result.checks["cpu_quote_fetched"] is True
        assert result.checks["cpu_quote_verified"] is True
        assert result.checks["tls_binding_verified"] is True
        assert result.checks["gpu_quote_fetched"] is True
        assert result.checks["gpu_quote_verified"] is True
        assert result.checks["gpu_binding_verified"] is True
        assert result.checks["workload_binding_verified"] is True
        assert result.checks["proof_of_cloud_verified"] is True
        assert result.errors == []

    def test_vm_without_gpu(self):
        tls_fp, cpu_result, _, _, no_gpu_json, workload_pass, poc_pass = _make_test_data()

        with patch(f"{_M}._get_tls_cert_fingerprint", return_value=tls_fp), \
             patch(f"{_M}.check_cpu_attestation", return_value=cpu_result), \
             patch(f"{_M}.verify_workload", return_value=workload_pass), \
             patch(f"{_M}.check_proof_of_cloud", return_value=poc_pass), \
             patch(f"{_M}.requests") as mock_req:
            mock_req.get.side_effect = [
                _mock_response("fake_cpu_quote"),
                _mock_response(no_gpu_json, content_type="application/json"),
                _mock_response("version: '3'\nservices: {}"),
            ]
            result = check_secret_vm("https://test-vm:29343")

        assert result.valid is True
        assert result.checks["tls_binding_verified"] is True
        assert result.checks["gpu_quote_fetched"] is False
        assert "gpu_quote_verified" not in result.checks
        assert "gpu_binding_verified" not in result.checks
        assert result.checks["workload_binding_verified"] is True
        assert result.checks["proof_of_cloud_verified"] is True

    def test_proof_of_cloud_failure(self):
        tls_fp, cpu_result, _, _, no_gpu_json, workload_pass, _ = _make_test_data()
        poc_fail = AttestationResult(
            valid=False, attestation_type="PROOF-OF-CLOUD",
            checks={"proof_of_cloud_verified": False},
            report={"proof_of_cloud": {"origin": None, "proof_of_cloud": False}},
            errors=["Proof-of-cloud endpoint reported proof_of_cloud=false"],
        )
        with patch(f"{_M}._get_tls_cert_fingerprint", return_value=tls_fp), \
             patch(f"{_M}.check_cpu_attestation", return_value=cpu_result), \
             patch(f"{_M}.verify_workload", return_value=workload_pass), \
             patch(f"{_M}.check_proof_of_cloud", return_value=poc_fail), \
             patch(f"{_M}.requests") as mock_req:
            mock_req.get.side_effect = [
                _mock_response("fake_cpu_quote"),
                _mock_response(no_gpu_json, content_type="application/json"),
                _mock_response("version: '3'\nservices: {}"),
            ]
            result = check_secret_vm("https://test-vm:29343")

        assert result.valid is False
        assert result.checks["proof_of_cloud_verified"] is False
        assert any("proof_of_cloud" in e.lower() or "Proof-of-cloud" in e for e in result.errors)

    def test_tls_binding_failure(self):
        tls_fp, cpu_result, _, _, no_gpu_json, workload_pass, poc_pass = _make_test_data()
        # Use wrong TLS fingerprint
        wrong_tls = bytes.fromhex("ff" * 32)

        with patch(f"{_M}._get_tls_cert_fingerprint", return_value=wrong_tls), \
             patch(f"{_M}.check_cpu_attestation", return_value=cpu_result), \
             patch(f"{_M}.verify_workload", return_value=workload_pass), \
             patch(f"{_M}.check_proof_of_cloud", return_value=poc_pass), \
             patch(f"{_M}.requests") as mock_req:
            mock_req.get.side_effect = [
                _mock_response("fake_cpu_quote"),
                _mock_response(no_gpu_json, content_type="application/json"),
                _mock_response("version: '3'\nservices: {}"),
            ]
            result = check_secret_vm("https://test-vm:29343")

        assert result.valid is False
        assert result.checks["tls_binding_verified"] is False
        assert any("TLS binding failed" in e for e in result.errors)

    def test_gpu_binding_failure(self):
        tls_fp, cpu_result, gpu_result, _, _, workload_pass, poc_pass = _make_test_data()
        # GPU JSON with wrong nonce
        wrong_gpu_json = json.dumps({"nonce": "dd" * 32, "arch": "HOPPER", "evidence_list": []})

        with patch(f"{_M}._get_tls_cert_fingerprint", return_value=tls_fp), \
             patch(f"{_M}.check_cpu_attestation", return_value=cpu_result), \
             patch(f"{_M}.check_nvidia_gpu_attestation", return_value=gpu_result), \
             patch(f"{_M}.verify_workload", return_value=workload_pass), \
             patch(f"{_M}.check_proof_of_cloud", return_value=poc_pass), \
             patch(f"{_M}.requests") as mock_req:
            mock_req.get.side_effect = [
                _mock_response("fake_cpu_quote"),
                _mock_response(wrong_gpu_json, content_type="application/json"),
                _mock_response("version: '3'\nservices: {}"),
            ]
            result = check_secret_vm("https://test-vm:29343")

        assert result.valid is False
        assert result.checks["gpu_binding_verified"] is False
        assert any("GPU binding failed" in e for e in result.errors)

    def test_cpu_attestation_failure(self):
        tls_fp, _, _, _, no_gpu_json, workload_pass, poc_pass = _make_test_data()
        bad_cpu = AttestationResult(
            valid=False, attestation_type="TDX",
            checks={"quote_parsed": True, "quote_verified": False},
            report={"report_data": "aa" * 32 + "bb" * 32},
            errors=["Quote verification failed"],
        )

        with patch(f"{_M}._get_tls_cert_fingerprint", return_value=tls_fp), \
             patch(f"{_M}.check_cpu_attestation", return_value=bad_cpu), \
             patch(f"{_M}.verify_workload", return_value=workload_pass), \
             patch(f"{_M}.check_proof_of_cloud", return_value=poc_pass), \
             patch(f"{_M}.requests") as mock_req:
            mock_req.get.side_effect = [
                _mock_response("fake_cpu_quote"),
                _mock_response(no_gpu_json, content_type="application/json"),
                _mock_response("version: '3'\nservices: {}"),
            ]
            result = check_secret_vm("https://test-vm:29343")

        assert result.valid is False
        assert result.checks["cpu_quote_verified"] is False

    def test_gpu_attestation_failure(self):
        tls_fp, cpu_result, _, gpu_json, _, workload_pass, poc_pass = _make_test_data()
        bad_gpu = AttestationResult(
            valid=False, attestation_type="NVIDIA-GPU",
            checks={"platform_jwt_signature": False},
            report={},
            errors=["JWT signature verification failed"],
        )

        with patch(f"{_M}._get_tls_cert_fingerprint", return_value=tls_fp), \
             patch(f"{_M}.check_cpu_attestation", return_value=cpu_result), \
             patch(f"{_M}.check_nvidia_gpu_attestation", return_value=bad_gpu), \
             patch(f"{_M}.verify_workload", return_value=workload_pass), \
             patch(f"{_M}.check_proof_of_cloud", return_value=poc_pass), \
             patch(f"{_M}.requests") as mock_req:
            mock_req.get.side_effect = [
                _mock_response("fake_cpu_quote"),
                _mock_response(gpu_json, content_type="application/json"),
                _mock_response("version: '3'\nservices: {}"),
            ]
            result = check_secret_vm("https://test-vm:29343")

        assert result.valid is False
        assert result.checks["gpu_quote_verified"] is False


# ---------------------------------------------------------------------------
# RTMR3 calculation (with and without docker-files)
# ---------------------------------------------------------------------------

class TestCalculateRtmr3:
    COMPOSE = "services:\n  app:\n    image: nginx\n"
    ROOTFS = "de" * 32
    DOCKER_FILES = b"pretend this is a tar"
    import hashlib as _h
    DOCKER_FILES_SHA = _h.sha256(DOCKER_FILES).hexdigest()

    def test_different_without_and_with_digest(self):
        from secretvm.verify.workload import _calculate_rtmr3
        without = _calculate_rtmr3(self.COMPOSE, self.ROOTFS)
        with_digest = _calculate_rtmr3(self.COMPOSE, self.ROOTFS, self.DOCKER_FILES_SHA)
        assert without != with_digest
        assert len(without) == 96 and len(with_digest) == 96

    def test_normalizes_0x_and_uppercase(self):
        from secretvm.verify.workload import _calculate_rtmr3
        lower = _calculate_rtmr3(self.COMPOSE, self.ROOTFS, self.DOCKER_FILES_SHA)
        with_prefix = _calculate_rtmr3(self.COMPOSE, self.ROOTFS, "0x" + self.DOCKER_FILES_SHA)
        upper = _calculate_rtmr3(self.COMPOSE, self.ROOTFS, self.DOCKER_FILES_SHA.upper())
        assert with_prefix == lower
        assert upper == lower


# ---------------------------------------------------------------------------
# Workload verification (resolve_secretvm_version + verify_tdx_workload)
# ---------------------------------------------------------------------------

DOCKER_QUOTE_FILE = FIXTURES_DIR / "tdx_cpu_docker_check_quote.txt"
DOCKER_COMPOSE_FILE = FIXTURES_DIR / "tdx_cpu_docker_check_compose.yaml"


@pytest.fixture
def docker_quote():
    return DOCKER_QUOTE_FILE.read_text()


@pytest.fixture
def docker_compose():
    return DOCKER_COMPOSE_FILE.read_text()


class TestResolveSecretvmVersion:
    def test_resolves_known_quote(self, docker_quote):
        v = resolve_secretvm_version(docker_quote)
        assert v is not None
        assert v["template_name"] == "small"
        assert v["artifacts_ver"].startswith("v0.0.")

    def test_returns_none_for_unknown_mrtd(self, docker_quote):
        raw = bytearray(bytes.fromhex(docker_quote.strip()))
        # MRTD is at offset 48+136=184, length 48 bytes -- flip first byte
        raw[184] ^= 0xFF
        v = resolve_secretvm_version(bytes(raw).hex())
        assert v is None

    def test_returns_none_for_garbage_input(self):
        v = resolve_secretvm_version("not-a-hex-quote!!!")
        assert v is None


class TestVerifyTdxWorkload:
    def test_authentic_match(self, docker_quote, docker_compose):
        r = verify_tdx_workload(docker_quote, docker_compose)
        assert r.status == "authentic_match"
        assert r.template_name == "small"
        assert r.artifacts_ver is not None
        assert r.artifacts_ver.startswith("v0.0.")
        assert r.env == "prod"

    def test_format_authentic_match(self, docker_quote, docker_compose):
        r = verify_tdx_workload(docker_quote, docker_compose)
        out = format_workload_result(r)
        assert "Confirmed" in out
        assert "docker-compose" in out

    def test_authentic_mismatch_when_compose_tampered(self, docker_quote, docker_compose):
        tampered = docker_compose + "\n# tampered"
        r = verify_tdx_workload(docker_quote, tampered)
        assert r.status == "authentic_mismatch"
        # Version info must still be populated even on mismatch
        assert r.template_name is not None
        assert r.artifacts_ver is not None

    def test_format_authentic_mismatch(self, docker_quote, docker_compose):
        r = verify_tdx_workload(docker_quote, docker_compose + "\n# bad")
        out = format_workload_result(r)
        assert "Confirmed" in out  # SecretVM line is present
        assert "does not match" in out

    def test_not_authentic_for_unknown_mrtd(self, docker_quote, docker_compose):
        raw = bytearray(bytes.fromhex(docker_quote.strip()))
        raw[184] ^= 0xFF  # corrupt MRTD
        r = verify_tdx_workload(bytes(raw).hex(), docker_compose)
        assert r.status == "not_authentic"

    def test_not_authentic_for_garbage_input(self, docker_compose):
        r = verify_tdx_workload("not-hex-at-all!!!", docker_compose)
        assert r.status == "not_authentic"

    def test_format_not_authentic(self):
        from secretvm.verify import WorkloadResult
        r = WorkloadResult(status="not_authentic")
        out = format_workload_result(r)
        assert "authentic SecretVM" in out


class TestCheckTdxCpuAttestationDockerQuote:
    """Crypto verification using the docker-check quote file."""

    def test_valid_quote_passes_all_checks(self, docker_quote):
        result = check_tdx_cpu_attestation(docker_quote)
        assert result.valid is True
        assert result.checks["quote_parsed"] is True
        assert result.checks["quote_verified"] is True
        assert result.errors == []

    def test_corrupted_quote_fails_signature(self, docker_quote):
        raw = bytearray(bytes.fromhex(docker_quote.strip()))
        # Flip a byte inside the ECDSA quote signature area (offset 636)
        raw[636] ^= 0xFF
        result = check_tdx_cpu_attestation(bytes(raw).hex())
        assert result.checks["quote_verified"] is False
        assert result.valid is False

    def test_invalid_hex_fails_parse(self):
        result = check_tdx_cpu_attestation("not-valid-hex!!!")
        assert result.valid is False
        assert result.checks["quote_parsed"] is False

    def test_truncated_quote_fails_parse(self):
        result = check_tdx_cpu_attestation("aa" * 100)
        assert result.valid is False
        assert result.checks["quote_parsed"] is False

    def test_corrupted_attestation_crypto_fails(self, docker_quote):
        """A cryptographically forged quote must be rejected."""
        raw = bytearray(bytes.fromhex(docker_quote.strip()))
        raw[636] ^= 0xFF
        crypto_result = check_tdx_cpu_attestation(bytes(raw).hex())
        assert crypto_result.valid is False


# ---------------------------------------------------------------------------
# Generic verifyWorkload + verifySevWorkload
# ---------------------------------------------------------------------------

AMD_DOCKER_QUOTE = (FIXTURES_DIR / "amd_cpu_docker_check_quote.txt").read_text()
AMD_DOCKER_COMPOSE = (FIXTURES_DIR / "amd_cpu_docker_check_compose.yaml").read_text()


class TestVerifyWorkload:
    """verify_workload auto-dispatches to the right implementation."""

    def test_delegates_to_tdx_for_tdx_quote(self, docker_quote, docker_compose):
        r = verify_workload(docker_quote, docker_compose)
        assert r.status == "authentic_match"

    def test_tdx_mismatch_via_generic(self, docker_quote, docker_compose):
        r = verify_workload(docker_quote, docker_compose + "\n# tampered")
        assert r.status == "authentic_mismatch"

    def test_tdx_not_authentic_corrupted_mrtd(self, docker_quote, docker_compose):
        raw = bytearray(bytes.fromhex(docker_quote.strip()))
        raw[184] ^= 0xFF
        r = verify_workload(bytes(raw).hex(), docker_compose)
        assert r.status == "not_authentic"

    def test_sev_docker_check_authentic_match(self):
        r = verify_workload(AMD_DOCKER_QUOTE, AMD_DOCKER_COMPOSE)
        assert r.status == "authentic_match"
        assert r.template_name == "small"
        assert r.artifacts_ver == "v0.0.25"
        assert r.env == "prod"

    def test_sev_authentic_mismatch_on_compose_change(self, docker_compose):
        # amd_cpu_quote.txt (v0.0.25 prod) is in the registry;
        # docker_compose (TDX compose) doesn't match its measurement.
        amd_quote = (FIXTURES_DIR / "amd_cpu_quote.txt").read_text()
        r = verify_workload(amd_quote, docker_compose)
        assert r.status == "authentic_mismatch"
        assert r.template_name == "small"
        assert r.artifacts_ver == "v0.0.25"

    def test_returns_not_authentic_for_unknown_input(self, docker_compose):
        r = verify_workload("not-a-valid-quote", docker_compose)
        assert r.status == "not_authentic"


class TestVerifySevWorkload:
    """verify_sev_workload — real GCTX-based implementation."""

    def test_authentic_match_for_correct_compose(self):
        r = verify_sev_workload(AMD_DOCKER_QUOTE, AMD_DOCKER_COMPOSE)
        assert r.status == "authentic_match"
        assert r.template_name == "small"
        assert r.artifacts_ver == "v0.0.25"
        assert r.env == "prod"

    def test_authentic_mismatch_for_wrong_compose(self):
        r = verify_sev_workload(AMD_DOCKER_QUOTE, AMD_DOCKER_COMPOSE + "\n# tampered")
        assert r.status == "authentic_mismatch"
        assert r.template_name == "small"
        assert r.artifacts_ver == "v0.0.25"
        assert r.env == "prod"

    def test_authentic_mismatch_for_corrupted_measurement(self):
        """A quote with a flipped measurement byte still has a recognised version;
        the workload layer reports authentic_mismatch (the crypto layer would catch
        the tampering via VCEK signature verification)."""
        import base64
        raw = bytearray(base64.b64decode(AMD_DOCKER_QUOTE.strip()))
        raw[0x090] ^= 0xFF  # flip first byte of measurement field
        corrupted = base64.b64encode(bytes(raw)).decode()
        r = verify_sev_workload(corrupted, AMD_DOCKER_COMPOSE)
        assert r.status == "authentic_mismatch"
        assert r.artifacts_ver == "v0.0.25"

    def test_not_authentic_for_garbled_input(self, docker_compose):
        r = verify_sev_workload("not-valid-base64!!!", docker_compose)
        assert r.status == "not_authentic"

    def test_authentic_mismatch_for_mismatched_compose(self, docker_compose):
        # amd_cpu_quote.txt (v0.0.25 prod) is in the registry;
        # docker_compose (TDX compose) doesn't match its measurement.
        amd_quote = (FIXTURES_DIR / "amd_cpu_quote.txt").read_text()
        r = verify_sev_workload(amd_quote, docker_compose)
        assert r.status == "authentic_mismatch"
        assert r.template_name == "small"
        assert r.artifacts_ver == "v0.0.25"
