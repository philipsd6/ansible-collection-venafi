"""
Regression tests for venafi_certificate key-type handling (bundled with the vcert 0.22.1 uptake):

  * ECDSA idempotency: an already-correct ECDSA key must NOT be judged "wrong" just because the
    requested curve casing differs from vcert's normalized value (user "P256" vs SDK "p256").
    Before the fix `_check_private_key_correct()` returned False for a matching key, so the cert
    re-enrolled on every run.

  * argspec hardening: `_get_key_type()` must fall back to the documented defaults (ECDSA -> P521,
    RSA -> 2048) instead of building KeyType(..., None) and crashing when the option is omitted.

  * Ed25519: `privatekey_type=ECDSA` + `privatekey_curve=ed25519` builds an Ed25519 KeyType
    (requires vcert>=0.22.0).

  * test_mode enrollment: with `test_mode: true` the module uses vcert's FakeConnection; a
    duplicate `read_zone_conf` in vcert 0.21.1 raised NotImplementedError and broke enrollment.
    vcert 0.22.1 fixes it, so a test_mode enroll must write the certificate and key.
"""
import os
import unittest
from collections import defaultdict
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from plugins.modules.venafi_certificate import VCertificate
from vcert import ZoneConfig, CertField, KeyType

CERT_PATH = "/tmp/kt_cert.pem"
CHAIN_PATH = "/tmp/kt_chain.pem"
PRIV_PATH = "/tmp/kt_priv.pem"


class _Fail(Exception):
    pass


class FakeModule(object):
    def __init__(self, params):
        self.fail_code = None
        self.exit_code = None
        self.warn = str
        self.check_mode = False
        self.params = defaultdict(lambda: None)
        self.params.update(params)

    def exit_json(self, **kwargs):
        self.exit_code = kwargs

    def fail_json(self, **kwargs):
        self.fail_code = kwargs
        raise _Fail(kwargs.get("msg"))

    def atomic_move(self, src, dst):
        os.replace(src, dst)

    def load_file_common_arguments(self, params):
        return {}

    def set_fs_attributes_if_different(self, file_args, changed):
        return False


BASE_PARAMS = {
    "cert_path": CERT_PATH,
    "chain_path": CHAIN_PATH,
    "privatekey_path": PRIV_PATH,
    "common_name": "kt.venafi.example.com",
    "before_expired_hours": 72,
    "test_mode": True,
    "csr_origin": "local",
    "privatekey_reuse": True,
    "issuer_hint": "DEFAULT",
    "chain_option": "last",
    "zone": "",
}


def _rm(*paths):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


def _write_ec_key(path, curve):
    key = ec.generate_private_key(curve)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem)


def _build(extra=None, mock_connection=True):
    params = dict(BASE_PARAMS)
    if extra:
        params.update(extra)
    vc = VCertificate(FakeModule(params))
    if mock_connection:
        conn = mock.Mock()
        conn.read_zone_conf.return_value = ZoneConfig(
            organization=CertField(""), organizational_unit=CertField(""),
            country=CertField(""), province=CertField(""), locality=CertField(""),
            policy=None, key_type=None,
        )
        vc.connection = conn
    return vc


class TestEcdsaIdempotency(unittest.TestCase):
    def setUp(self):
        _rm(CERT_PATH, CHAIN_PATH, PRIV_PATH)
        _write_ec_key(PRIV_PATH, ec.SECP256R1())

    def tearDown(self):
        _rm(CERT_PATH, CHAIN_PATH, PRIV_PATH)

    def test_uppercase_curve_matches_lowercase_sdk_value(self):
        # vcert reports the P-256 key as curve "p256"; the user requests "P256".
        vc = _build({"privatekey_type": "ECDSA", "privatekey_curve": "P256"})
        self.assertTrue(
            vc._check_private_key_correct(),
            "matching ECDSA key judged wrong due to curve casing -> re-enroll churn")

    def test_hyphenated_curve_matches(self):
        vc = _build({"privatekey_type": "ECDSA", "privatekey_curve": "P-256"})
        self.assertTrue(vc._check_private_key_correct())

    def test_wrong_curve_still_detected(self):
        # Negative control: the normalization must not mask a genuine curve mismatch.
        vc = _build({"privatekey_type": "ECDSA", "privatekey_curve": "P384"})
        self.assertFalse(vc._check_private_key_correct())


class TestGetKeyTypeDefaults(unittest.TestCase):
    def setUp(self):
        _rm(CERT_PATH, CHAIN_PATH, PRIV_PATH)

    def tearDown(self):
        _rm(CERT_PATH, CHAIN_PATH, PRIV_PATH)

    def test_ecdsa_without_curve_defaults_to_p521(self):
        vc = _build({"privatekey_type": "ECDSA"})
        kt = vc._get_key_type()
        self.assertEqual(kt.key_type, KeyType.ECDSA)
        self.assertEqual(kt.option, "p521")

    def test_rsa_without_size_defaults_to_2048(self):
        vc = _build({"privatekey_type": "RSA"})
        kt = vc._get_key_type()
        self.assertEqual(kt.key_type, KeyType.RSA)
        self.assertEqual(kt.option, 2048)

    def test_ed25519_curve(self):
        vc = _build({"privatekey_type": "ECDSA", "privatekey_curve": "ed25519"})
        kt = vc._get_key_type()
        self.assertEqual(kt.option, "ed25519")


class TestTestModeEnroll(unittest.TestCase):
    """Exercises the real vcert FakeConnection (no mock) -> guards the vcert 0.22.1
    duplicate-read_zone_conf fix and the pin floor."""

    def setUp(self):
        _rm(CERT_PATH, CHAIN_PATH, PRIV_PATH)

    def tearDown(self):
        _rm(CERT_PATH, CHAIN_PATH, PRIV_PATH)

    def test_test_mode_enroll_writes_cert_and_key(self):
        vc = _build(mock_connection=False)  # real FakeConnection from test_mode: true
        vc.enroll()
        self.assertTrue(os.path.exists(CERT_PATH), "test_mode enroll did not write the certificate")
        self.assertTrue(os.path.exists(PRIV_PATH), "test_mode enroll did not write the private key")


if __name__ == "__main__":
    unittest.main()
