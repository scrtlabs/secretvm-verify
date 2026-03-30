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
    check_amd_cpu_attestation,
    check_cpu_attestation,
    check_nvidia_gpu_attestation,
    check_secret_vm,
    check_tdx_cpu_attestation,
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
        assert result.checks["cert_chain_valid"] is True
        assert result.checks["qe_report_signature_valid"] is True
        assert result.checks["attestation_key_bound"] is True
        assert result.checks["quote_signature_valid"] is True
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
        assert result.checks["quote_signature_valid"] is False


# ---------------------------------------------------------------------------
# AMD SEV-SNP
# ---------------------------------------------------------------------------

class TestAmdAttestation:
    def test_valid_report(self, amd_quote):
        result = check_amd_cpu_attestation(amd_quote, product="Genoa")
        assert isinstance(result, AttestationResult)
        assert result.attestation_type == "SEV-SNP"
        assert result.valid is True
        assert result.checks["report_parsed"] is True
        assert result.checks["vcek_fetched"] is True
        assert result.checks["cert_chain_valid"] is True
        assert result.checks["report_signature_valid"] is True
        assert result.errors == []

    def test_report_fields(self, amd_quote):
        result = check_amd_cpu_attestation(amd_quote, product="Genoa")
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
        result = check_amd_cpu_attestation(amd_quote)
        if result.checks.get("vcek_fetched") is False and "429" in str(result.errors):
            pytest.skip("AMD KDS rate-limited")
        assert result.valid is True
        assert result.report["product"] == "Genoa"

    def test_invalid_base64(self):
        result = check_amd_cpu_attestation("!!!not-base64!!!")
        assert result.valid is False
        assert result.checks["report_parsed"] is False
        assert len(result.errors) > 0

    def test_truncated_report(self):
        import base64
        short = base64.b64encode(b"\x00" * 100).decode()
        result = check_amd_cpu_attestation(short)
        assert result.valid is False
        assert result.checks["report_parsed"] is False

    def test_empty_input(self):
        result = check_amd_cpu_attestation("")
        assert result.valid is False

    def test_wrong_product(self, amd_quote):
        result = check_amd_cpu_attestation(amd_quote, product="Milan")
        assert result.valid is False
        assert result.checks.get("vcek_fetched") is False

    def test_corrupted_signature(self, amd_quote):
        """Flip a byte in the report body to break the signature."""
        import base64
        raw = base64.b64decode(amd_quote.strip())
        corrupted = bytearray(raw)
        corrupted[0x090] ^= 0xFF  # corrupt the measurement field
        data = base64.b64encode(corrupted).decode()
        result = check_amd_cpu_attestation(data, product="Genoa")
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
    report_data = tls_hex + nonce_hex
    tls_fp = bytes.fromhex(tls_hex)

    cpu_result = AttestationResult(
        valid=True, attestation_type="TDX",
        checks={"quote_parsed": True, "quote_signature_valid": True},
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

    return tls_fp, cpu_result, gpu_result, gpu_json, no_gpu_json


class TestSecretVm:
    def test_unreachable_host(self):
        result = check_secret_vm("https://192.0.2.1:29343")
        assert result.valid is False
        assert result.attestation_type == "SECRET-VM"
        assert result.checks.get("tls_cert_obtained") is False
        assert len(result.errors) > 0

    def test_invalid_url(self):
        result = check_secret_vm("")
        assert result.valid is False

    def test_url_parsing(self):
        from secretvm.verify import _parse_vm_url

        assert _parse_vm_url("myhost") == ("myhost", 29343)
        assert _parse_vm_url("myhost:1234") == ("myhost", 1234)
        assert _parse_vm_url("https://myhost:5555") == ("myhost", 5555)
        assert _parse_vm_url("https://myhost") == ("myhost", 29343)

    def test_vm_with_gpu_all_pass(self):
        tls_fp, cpu_result, gpu_result, gpu_json, _ = _make_test_data()

        with patch(f"{_M}._get_tls_cert_fingerprint", return_value=tls_fp), \
             patch(f"{_M}.check_cpu_attestation", return_value=cpu_result), \
             patch(f"{_M}.check_nvidia_gpu_attestation", return_value=gpu_result), \
             patch(f"{_M}.requests") as mock_req:
            mock_req.get.side_effect = [
                _mock_response("fake_cpu_quote"),
                _mock_response(gpu_json, content_type="application/json"),
            ]
            result = check_secret_vm("https://test-vm:29343")

        assert result.valid is True
        assert result.attestation_type == "SECRET-VM"
        assert result.checks["tls_cert_obtained"] is True
        assert result.checks["cpu_quote_fetched"] is True
        assert result.checks["cpu_attestation_valid"] is True
        assert result.checks["tls_binding"] is True
        assert result.checks["gpu_quote_fetched"] is True
        assert result.checks["gpu_attestation_valid"] is True
        assert result.checks["gpu_binding"] is True
        assert result.errors == []

    def test_vm_without_gpu(self):
        tls_fp, cpu_result, _, _, no_gpu_json = _make_test_data()

        with patch(f"{_M}._get_tls_cert_fingerprint", return_value=tls_fp), \
             patch(f"{_M}.check_cpu_attestation", return_value=cpu_result), \
             patch(f"{_M}.requests") as mock_req:
            mock_req.get.side_effect = [
                _mock_response("fake_cpu_quote"),
                _mock_response(no_gpu_json, content_type="application/json"),
            ]
            result = check_secret_vm("https://test-vm:29343")

        assert result.valid is True
        assert result.checks["tls_binding"] is True
        assert result.checks["gpu_quote_fetched"] is False
        assert "gpu_attestation_valid" not in result.checks
        assert "gpu_binding" not in result.checks

    def test_tls_binding_failure(self):
        tls_fp, cpu_result, _, _, no_gpu_json = _make_test_data()
        # Use wrong TLS fingerprint
        wrong_tls = bytes.fromhex("ff" * 32)

        with patch(f"{_M}._get_tls_cert_fingerprint", return_value=wrong_tls), \
             patch(f"{_M}.check_cpu_attestation", return_value=cpu_result), \
             patch(f"{_M}.requests") as mock_req:
            mock_req.get.side_effect = [
                _mock_response("fake_cpu_quote"),
                _mock_response(no_gpu_json, content_type="application/json"),
            ]
            result = check_secret_vm("https://test-vm:29343")

        assert result.valid is False
        assert result.checks["tls_binding"] is False
        assert any("TLS binding failed" in e for e in result.errors)

    def test_gpu_binding_failure(self):
        tls_fp, cpu_result, gpu_result, _, _ = _make_test_data()
        # GPU JSON with wrong nonce
        wrong_gpu_json = json.dumps({"nonce": "dd" * 32, "arch": "HOPPER", "evidence_list": []})

        with patch(f"{_M}._get_tls_cert_fingerprint", return_value=tls_fp), \
             patch(f"{_M}.check_cpu_attestation", return_value=cpu_result), \
             patch(f"{_M}.check_nvidia_gpu_attestation", return_value=gpu_result), \
             patch(f"{_M}.requests") as mock_req:
            mock_req.get.side_effect = [
                _mock_response("fake_cpu_quote"),
                _mock_response(wrong_gpu_json, content_type="application/json"),
            ]
            result = check_secret_vm("https://test-vm:29343")

        assert result.valid is False
        assert result.checks["gpu_binding"] is False
        assert any("GPU binding failed" in e for e in result.errors)

    def test_cpu_attestation_failure(self):
        tls_fp, _, _, _, no_gpu_json = _make_test_data()
        bad_cpu = AttestationResult(
            valid=False, attestation_type="TDX",
            checks={"quote_parsed": True, "quote_signature_valid": False},
            report={"report_data": "aa" * 32 + "bb" * 32},
            errors=["Quote signature verification failed"],
        )

        with patch(f"{_M}._get_tls_cert_fingerprint", return_value=tls_fp), \
             patch(f"{_M}.check_cpu_attestation", return_value=bad_cpu), \
             patch(f"{_M}.requests") as mock_req:
            mock_req.get.side_effect = [
                _mock_response("fake_cpu_quote"),
                _mock_response(no_gpu_json, content_type="application/json"),
            ]
            result = check_secret_vm("https://test-vm:29343")

        assert result.valid is False
        assert result.checks["cpu_attestation_valid"] is False

    def test_gpu_attestation_failure(self):
        tls_fp, cpu_result, _, gpu_json, _ = _make_test_data()
        bad_gpu = AttestationResult(
            valid=False, attestation_type="NVIDIA-GPU",
            checks={"platform_jwt_signature": False},
            report={},
            errors=["JWT signature verification failed"],
        )

        with patch(f"{_M}._get_tls_cert_fingerprint", return_value=tls_fp), \
             patch(f"{_M}.check_cpu_attestation", return_value=cpu_result), \
             patch(f"{_M}.check_nvidia_gpu_attestation", return_value=bad_gpu), \
             patch(f"{_M}.requests") as mock_req:
            mock_req.get.side_effect = [
                _mock_response("fake_cpu_quote"),
                _mock_response(gpu_json, content_type="application/json"),
            ]
            result = check_secret_vm("https://test-vm:29343")

        assert result.valid is False
        assert result.checks["gpu_attestation_valid"] is False
