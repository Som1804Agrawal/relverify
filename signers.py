"""Signing keys that live OUTSIDE this program (HSM, smart card, YubiKey, cloud KMS).
Every place that signs (releases, delegations, revocation lists, transparency tree heads) accepts any object with
  .alg            -> "ed25519" or "rsa-pss"
  .public_key()   -> a cryptography public key object
  .sign_data(b)   -> signature bytes (the private key never leaves the device)
Use  --key pkcs11:lib=/path/libsofthsm2.so;token=MyToken;key=release-key;alg=rsa-pss  on the command line.
The PIN is read from the RELVERIFY_PIN environment variable or prompted for; it is never put on the command line.

NOTE: Pkcs11Signer is written against the PyKCS11 API (pip install PyKCS11) and could NOT be run against real hardware
in the build environment. Test it with SoftHSM2 before relying on it. The interface and everything that uses it
is tested with an in-memory stand-in (see tests)."""
import getpass, os

class Pkcs11Signer:
    def __init__(self, lib, token, key, alg="rsa-pss", pin=None):
        try:
            import PyKCS11
        except ImportError:
            raise RuntimeError("PKCS#11 support needs the PyKCS11 package (pip install PyKCS11)")
        from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
        self.alg, self._K = alg, PyKCS11
        self._lib = PyKCS11.PyKCS11Lib(); self._lib.load(lib)
        slots = [s for s in self._lib.getSlotList(tokenPresent=True) if self._lib.getTokenInfo(s).label.strip() == token]
        if not slots:
            raise RuntimeError(f"no token labelled {token!r} found")
        self._session = self._lib.openSession(slots[0], PyKCS11.CKF_SERIAL_SESSION)
        self._session.login(pin or os.environ.get("RELVERIFY_PIN") or getpass.getpass(f"PIN for token {token}: "))
        find = lambda cls: self._session.findObjects([(PyKCS11.CKA_CLASS, cls), (PyKCS11.CKA_LABEL, key)])
        privs, pubs = find(PyKCS11.CKO_PRIVATE_KEY), find(PyKCS11.CKO_PUBLIC_KEY)
        if not privs or not pubs:
            raise RuntimeError(f"key {key!r} not found on the token")
        self._priv = privs[0]
        a = self._session.getAttributeValue(pubs[0], [PyKCS11.CKA_MODULUS, PyKCS11.CKA_PUBLIC_EXPONENT, PyKCS11.CKA_EC_POINT])
        if alg == "rsa-pss":
            self._pub = rsa.RSAPublicNumbers(int.from_bytes(bytes(a[1]), "big"), int.from_bytes(bytes(a[0]), "big")).public_key()
        elif alg == "ed25519":
            point = bytes(a[2]); self._pub = ed25519.Ed25519PublicKey.from_public_bytes(point[-32:])  # strip DER wrapper
        else:
            raise ValueError("alg must be ed25519 or rsa-pss")

    def public_key(self):
        return self._pub

    def sign_data(self, data):
        K = self._K
        mech = (K.RSA_PSS_Mechanism(K.CKM_SHA256_RSA_PKCS_PSS, K.CKM_SHA256, K.CKG_MGF1_SHA256, 32) if self.alg == "rsa-pss"
                else K.Mechanism(K.CKM_EDDSA, None))
        return bytes(self._session.sign(self._priv, data, mech))

def from_spec(spec):
    """'pkcs11:lib=...;token=...;key=...;alg=rsa-pss' -> signer"""
    parts = dict(p.split("=", 1) for p in spec[len("pkcs11:"):].split(";") if "=" in p)
    missing = [k for k in ("lib", "token", "key") if k not in parts]
    if missing:
        raise ValueError(f"pkcs11 spec needs {missing}")
    return Pkcs11Signer(parts["lib"], parts["token"], parts["key"], parts.get("alg", "rsa-pss"))
