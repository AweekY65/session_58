"""manifest 签名 / 验签相关测试。"""

from __future__ import annotations

import base64
import json

from cryptography.exceptions import InvalidSignature

from ota.errors import ManifestError, SignatureError
from ota.keys import generate_keypair
from ota.manifest import (
    canonical_payload,
    load_and_verify,
    manifest_from_dict,
    sha256_hex,
    sign_manifest,
    verify_signature,
    with_tampered_field,
)

from tests.helpers import OTATestCase


FIELDS = {
    "version": "1.1.0",
    "image": "fw.bin",
    "size": 10,
    "sha256": "a" * 64,
    "created_at": "2026-09-28T00:00:00Z",
}


class ManifestCryptoTest(OTATestCase):
    def test_sign_and_verify_roundtrip(self):
        manifest = sign_manifest(FIELDS, self.private_key)
        manifest.verify_signature(self.public_key)  # 不抛异常即通过
        # 64 字节 Ed25519 签名
        self.assertEqual(len(manifest.signature), 64)

    def test_signature_payload_is_canonical_and_excludes_signature(self):
        manifest = sign_manifest(FIELDS, self.private_key)
        doc = manifest.to_dict()
        payload = canonical_payload(doc)
        self.assertNotIn(b"signature", payload)
        # 规范化：sort_keys + 紧凑分隔
        self.assertEqual(
            payload,
            json.dumps(FIELDS, sort_keys=True, separators=(",", ":")).encode(),
        )
        # 手工验签
        self.public_key.verify(
            base64.b64decode(doc["signature"]), payload
        )

    def test_wrong_key_rejected(self):
        manifest = sign_manifest(FIELDS, self.private_key)
        _, other_pub = generate_keypair()
        with self.assertRaises(SignatureError):
            manifest.verify_signature(other_pub)

    def test_raw_crypto_mismatch_raises_invalid_signature(self):
        # 证明底层确实是 Ed25519 验签（错误签名 -> InvalidSignature）
        manifest = sign_manifest(FIELDS, self.private_key)
        with self.assertRaises(InvalidSignature):
            self.public_key.verify(b"\x00" * 64, manifest.signing_payload())

    def test_tampered_version_field_rejected(self):
        manifest = sign_manifest(FIELDS, self.private_key)
        tampered = with_tampered_field(manifest, "version", "9.9.9")
        with self.assertRaises(SignatureError):
            verify_signature(tampered, self.public_key)

    def test_tampered_sha256_field_rejected(self):
        manifest = sign_manifest(FIELDS, self.private_key)
        tampered = with_tampered_field(manifest, "sha256", "b" * 64)
        with self.assertRaises(SignatureError):
            verify_signature(tampered, self.public_key)

    def test_missing_signature_rejected(self):
        with self.assertRaises(SignatureError):
            verify_signature({**FIELDS}, self.public_key)

    def test_missing_required_field_rejected(self):
        with self.assertRaises(ManifestError):
            sign_manifest({k: v for k, v in FIELDS.items() if k != "version"},
                          self.private_key)

    def test_bad_sha256_format_rejected(self):
        manifest = sign_manifest(FIELDS, self.private_key)
        doc = manifest.to_dict()
        doc["sha256"] = "not-a-hash"
        with self.assertRaises(ManifestError):
            manifest_from_dict(doc)

    def test_save_load_and_verify(self):
        data, _, _, manifest_path = self.make_signed_image("2.0.0")
        manifest = load_and_verify(manifest_path, self.public_key)
        self.assertEqual(manifest.version, "2.0.0")
        self.assertEqual(manifest.size, len(data))
        self.assertEqual(manifest.sha256, sha256_hex(data))

    def test_signed_file_wrong_key_rejected(self):
        _, _, _, manifest_path = self.make_signed_image("2.0.0")
        _, other_pub = generate_keypair()
        other_pub_path = f"{self.keydir}/other.pem"
        from ota.keys import save_public_key

        save_public_key(other_pub, other_pub_path)
        with self.assertRaises(SignatureError):
            load_and_verify(manifest_path, other_pub)
