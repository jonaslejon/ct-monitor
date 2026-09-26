#!/usr/bin/env python3
"""Precertificates are read from extra_data (RFC 6962 PrecertChainEntry)."""
import base64
import datetime
import importlib.util
import sys
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("ctm", HERE / "ct-monitor.py")
ctm = importlib.util.module_from_spec(spec)
_argv, sys.argv = sys.argv, ["ct-monitor"]
spec.loader.exec_module(ctm)
sys.argv = _argv


def make_cert_der(name="precert.example", poison=False, serial=1):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime(2026, 9, 25)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
               .public_key(key.public_key()).serial_number(serial)
               .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=90))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False))
    if poison:
        builder = builder.add_extension(x509.PrecertPoison(), critical=True)
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def precert_entry(der):
    # leaf: version(1) leaf_type(1) timestamp(8) entry_type(2)=1 issuer_key_hash(32) tbs_len(3) tbs
    tbs = b"\x30\x03\x02\x01\x01"  # not a certificate: what the old code tried to parse
    leaf = (b"\x00\x00" + (0).to_bytes(8, "big") + (1).to_bytes(2, "big") + b"\x00" * 32
            + len(tbs).to_bytes(3, "big") + tbs + b"\x00\x00")
    extra = len(der).to_bytes(3, "big") + der + (0).to_bytes(3, "big")
    return {"leaf_input": base64.b64encode(leaf).decode(), "extra_data": base64.b64encode(extra).decode()}


class TestPrecert(unittest.TestCase):
    def setUp(self):
        self.mon = ctm.CTLogMonitor(quiet=True)

    def test_precert_and_final_share_an_issuance_key(self):
        pre = x509.load_der_x509_certificate(make_cert_der("a.example", poison=True, serial=0xabc))
        fin = x509.load_der_x509_certificate(make_cert_der("a.example", serial=0xabc))
        other = x509.load_der_x509_certificate(make_cert_der("a.example", serial=0xabd))
        k_pre, is_pre = ctm.CTLogMonitor._issuance_identity(pre)
        k_fin, is_fin_pre = ctm.CTLogMonitor._issuance_identity(fin)
        self.assertTrue(is_pre)
        self.assertFalse(is_fin_pre)
        self.assertEqual(k_pre, k_fin)
        self.assertTrue(k_pre.endswith(":abc"))
        self.assertNotEqual(k_pre, ctm.CTLogMonitor._issuance_identity(other)[0])

    def test_processed_precert_carries_key_and_flag(self):
        e = precert_entry(make_cert_der("p.example", poison=True, serial=7))
        e["_v2"] = True
        (r,) = [r for r in self.mon.process_certificate(e) if r.name == "p.example"]
        self.assertTrue(r.precert)
        self.assertTrue(r.issuance_key.endswith(":7"))
        self.assertEqual(r.to_dict()["pc"], True)

    def test_extra_data_parser(self):
        der = make_cert_der()
        cert = ctm.CTLogMonitor._precert_from_extra_data(precert_entry(der)["extra_data"])
        self.assertIsNotNone(cert)
        self.assertIsNone(ctm.CTLogMonitor._precert_from_extra_data(base64.b64encode(b"\x00\x00").decode()))

    def test_precert_from_the_gap_free_fetcher_yields_its_names(self):
        e = precert_entry(make_cert_der("precert.example"))
        e["_v2"] = True
        self.assertIn("precert.example", {r.name for r in self.mon.process_certificate(e)})

    def test_precert_from_the_classic_loop_is_unchanged(self):
        e = precert_entry(make_cert_der("precert.example"))
        self.assertEqual(self.mon.process_certificate(e), [])


if __name__ == "__main__":
    unittest.main()
