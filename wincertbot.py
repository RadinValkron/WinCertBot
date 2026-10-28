import base64
import hashlib
import json
import os
import sys
import time

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID

APP_NAME = "WinCertBot-CLI"
LE_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
USER_AGENT = "WinCertBot-CLI/1.0"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def canonical_json(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def rsa_jwk(key):
    n = key.public_key().public_numbers()
    return {
        "e": b64url(n.e.to_bytes((n.e.bit_length() + 7) // 8, "big")),
        "kty": "RSA",
        "n": b64url(n.n.to_bytes((n.n.bit_length() + 7) // 8, "big")),
    }


def jwk_thumbprint(jwk):
    minimal = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    return b64url(hashlib.sha256(canonical_json(minimal)).digest())


def strip_wildcard(domain: str) -> str:
    return domain[2:] if domain.startswith("*.") else domain


def log(msg=""):
    print(msg, flush=True)


class AcmeClient:
    def __init__(self, directory_url):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.directory = self.session.get(directory_url, timeout=30).json()
        self.nonce = None
        self.account_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwk = rsa_jwk(self.account_key)
        self.thumbprint = jwk_thumbprint(self.jwk)
        self.kid = None

    def _nonce(self):
        if self.nonce:
            n, self.nonce = self.nonce, None
            return n
        r = self.session.head(self.directory["newNonce"], timeout=30)
        if r.status_code >= 400:
            r = self.session.get(self.directory["newNonce"], timeout=30)
        r.raise_for_status()
        nonce = r.headers.get("Replay-Nonce")
        if not nonce:
            raise RuntimeError("No Replay-Nonce from ACME server.")
        return nonce

    def _jws(self, url, payload, use_jwk=False):
        protected = {"alg": "RS256", "nonce": self._nonce(), "url": url}
        if use_jwk:
            protected["jwk"] = self.jwk
        else:
            if not self.kid:
                raise RuntimeError("Account not created yet.")
            protected["kid"] = self.kid
        protected64 = b64url(canonical_json(protected))
        payload64 = "" if payload is None else b64url(canonical_json(payload))
        signing_input = (protected64 + "." + payload64).encode("ascii")
        signature = self.account_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        body = {"protected": protected64, "payload": payload64, "signature": b64url(signature)}
        r = self.session.post(url, json=body,
                              headers={"Content-Type": "application/jose+json"}, timeout=45)
        rn = r.headers.get("Replay-Nonce")
        if rn:
            self.nonce = rn
        if r.status_code >= 400:
            try:
                detail = r.json()
            except Exception:
                detail = r.text[:1000]
            raise RuntimeError(f"ACME error ({r.status_code}): {detail}")
        ct = r.headers.get("Content-Type", "")
        if "json" in ct:
            try:
                return r.json(), r.headers
            except Exception:
                pass
        return r.text, r.headers

    def create_account(self, email):
        payload = {"termsOfServiceAgreed": True, "contact": [f"mailto:{email}"]}
        _, headers = self._jws(self.directory["newAccount"], payload, use_jwk=True)
        self.kid = headers.get("Location")
        if not self.kid:
            raise RuntimeError("No account URL received.")
        log("[+] ACME account created.")

    def post_as_get(self, url):
        return self._jws(url, None)[0]

    def create_order(self, domains):
        identifiers = [{"type": "dns", "value": strip_wildcard(d)} for d in domains]
        data, headers = self._jws(self.directory["newOrder"], {"identifiers": identifiers})
        url = headers.get("Location")
        if not url:
            raise RuntimeError("No order URL received.")
        return url, data

    def trigger_challenge(self, url):
        self._jws(url, {})

    def finalize(self, finalize_url, csr_der):
        return self._jws(finalize_url, {"csr": b64url(csr_der)})[0]

    def download_certificate(self, cert_url):
        return self._jws(cert_url, None)[0]


def wait_for_dns(name, expected, timeout=300):
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.timeout = 4
    resolver.lifetime = 8
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            answers = resolver.resolve(name, "TXT")
            values = []
            for a in answers:
                values.append("".join(
                    p.decode("utf-8") if isinstance(p, bytes) else str(p)
                    for p in a.strings
                ))
            if expected in values:
                log(f"[+] DNS verified: {name}")
                return
            log(f"[~] Not propagated yet: {name} (retry 10s)")
        except Exception:
            log(f"[~] Not visible yet: {name} (retry 10s)")
        time.sleep(10)
    raise RuntimeError(f"TXT record not found within timeout: {name}")


def poll_authorization(client, url, domain, timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        auth = client.post_as_get(url)
        status = auth.get("status")
        if status == "valid":
            log(f"[+] Validated: {domain}")
            return
        if status == "invalid":
            raise RuntimeError(f"Validation rejected for {domain}: {auth}")
        time.sleep(3)
    raise RuntimeError(f"Validation timed out: {domain}")


def issue_certificate(domains, email, output_dir):
    log(f"[*] Connecting to Let's Encrypt…")
    client = AcmeClient(LE_DIRECTORY)
    client.create_account(email)

    log("[*] Creating order…")
    order_url, order = client.create_order(domains)

    challenges = []
    authorizations = []
    seen = set()

    for auth_url in order.get("authorizations", []):
        auth = client.post_as_get(auth_url)
        if auth.get("status") == "valid":
            continue
        ident = auth.get("identifier", {}).get("value", "")
        ch = next((c for c in auth.get("challenges", []) if c.get("type") == "dns-01"), None)
        if not ch:
            raise RuntimeError(f"No DNS challenge for {ident}")
        key_auth = ch["token"] + "." + client.thumbprint
        txt_val = b64url(hashlib.sha256(key_auth.encode("ascii")).digest())
        txt_name = "_acme-challenge." + ident
        k = (txt_name, txt_val)
        if k not in seen:
            seen.add(k)
            challenges.append({"name": txt_name, "value": txt_val, "url": ch["url"]})
        authorizations.append({"url": auth_url, "domain": ident})

    if challenges:
        log("\n========== ADD THESE DNS TXT RECORDS ==========")
        for i, item in enumerate(challenges, 1):
            log(f"{i}) Type: TXT")
            log(f"   Name:  {item['name']}")
            log(f"   Value: {item['value']}")
            log("")
        log("Add records in your DNS panel, then press ENTER.")
        input()

        log("[*] Checking DNS propagation…")
        for item in challenges:
            wait_for_dns(item["name"], item["value"])

        log("[*] Triggering challenges…")
        for item in challenges:
            client.trigger_challenge(item["url"])

        for a in authorizations:
            poll_authorization(client, a["url"], a["domain"])

    log("[*] Generating key + CSR…")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, strip_wildcard(domains[0]))])
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]), critical=False
    )
    csr = builder.sign(private_key, hashes.SHA256())

    order = client.post_as_get(order_url)
    finalize_url = order.get("finalize")
    if not finalize_url:
        raise RuntimeError("No finalize URL in order.")

    client.finalize(finalize_url, csr.public_bytes(serialization.Encoding.DER))

    deadline = time.time() + 180
    while time.time() < deadline:
        order = client.post_as_get(order_url)
        status = order.get("status")
        if status == "valid":
            break
        if status == "invalid":
            raise RuntimeError(f"Order invalid: {order}")
        time.sleep(3)
    else:
        raise RuntimeError("Timeout waiting for issuance.")

    cert_url = order.get("certificate")
    if not cert_url:
        raise RuntimeError("No certificate URL.")
    cert_pem = client.download_certificate(cert_url)
    if "BEGIN CERTIFICATE" not in cert_pem:
        raise RuntimeError("Bad PEM response.")

    os.makedirs(output_dir, exist_ok=True)
    folder_name = domains[0].replace("*.", "wildcard_").replace(".", "_")
    folder = os.path.join(output_dir, folder_name)
    os.makedirs(folder, exist_ok=True)

    base_name = strip_wildcard(domains[0])
    key_path = os.path.join(folder, f"{base_name}.key")
    cert_path = os.path.join(folder, f"{base_name}.crt")
    bundle_path = os.path.join(folder, f"{base_name}.ca-bundle")

    blocks = []
    for b in cert_pem.split("-----END CERTIFICATE-----"):
        b = b.strip()
        if "BEGIN CERTIFICATE" in b:
            blocks.append(b + "\n-----END CERTIFICATE-----\n")

    leaf = blocks[0] if blocks else ""
    chain = "".join(blocks[1:]) if len(blocks) > 1 else ""

    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    with open(cert_path, "w", encoding="ascii", newline="\n") as f:
        f.write(leaf)
    with open(bundle_path, "w", encoding="ascii", newline="\n") as f:
        f.write(chain)

    log("\n[+] Certificate issued!")
    log(f"    Key:    {key_path}")
    log(f"    Cert:   {cert_path}")
    log(f"    Bundle: {bundle_path}")
    log("[!] Keep the .key file secret.")


def main():
    print("=" * 56)
    print("  WinCertBot CLI - Let's Encrypt DNS-01 (manual)")
    print("=" * 56)
    if len(sys.argv) >= 4:
        domains_raw, email, output = sys.argv[1], sys.argv[2], sys.argv[3]
    else:
        domains_raw = input("Domains (comma separated, * for wildcard): ").strip()
        email = input("Contact email: ").strip()
        default_out = os.path.join(os.path.expanduser("~"), "WinCertBot-Certificates")
        output = input(f"Output folder [{default_out}]: ").strip() or default_out

    domains = [x.strip().lower().rstrip(".") for x in domains_raw.split(",") if x.strip()]
    if not domains:
        print("[!] No domains provided."); return 1
    if "@" not in email:
        print("[!] Invalid email."); return 1
    for d in domains:
        bare = strip_wildcard(d)
        if "." not in bare or any(not p or len(p) > 63 for p in bare.split(".")):
            print(f"[!] Invalid domain: {d}"); return 1

    try:
        issue_certificate(domains, email, output)
        return 0
    except Exception as e:
        print(f"\n[!] ERROR: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())