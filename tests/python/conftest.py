"""Shared fixtures and paths for rpm_rs Python tests."""

import os

# Resolve paths relative to the repo root
REPO_ROOT = os.path.join(os.path.dirname(__file__), "../..")
ASSETS = os.path.join(REPO_ROOT, "tests/assets")

# --- RPM fixture paths ---

RPMS = os.path.join(ASSETS, "RPMS/v6")
SRPMS = os.path.join(ASSETS, "SRPMS/v6")

RPM_BASIC = os.path.join(RPMS, "rpm-basic-2.3.4-5.el9.noarch.rpm")
RPM_EMPTY = os.path.join(RPMS, "rpm-empty-0-0.x86_64.rpm")
RPM_FILE_ATTRS = os.path.join(RPMS, "rpm-file-attrs-1.0-1.noarch.rpm")
RPM_FILE_TYPES = os.path.join(RPMS, "rpm-file-types-1.0-1.noarch.rpm")
RPM_SPECIAL_FILES = os.path.join(RPMS, "rpm-special-files-1.0-1.noarch.rpm")
RPM_SCRIPTLETS = os.path.join(RPMS, "rpm-scriptlets-1.0-1.noarch.rpm")
RPM_RICH_DEPS = os.path.join(RPMS, "rpm-rich-deps-1.0-1.noarch.rpm")
RPM_HARDLINKS = os.path.join(RPMS, "rpm-hardlinks-1.0-1.noarch.rpm")
RPM_SIGNED = os.path.join(RPMS, "signed/rpm-basic-with-rsa4k-2.3.4-5.el9.noarch.rpm")
RPM_MULTI_SIGNED = os.path.join(
    RPMS, "signed/rpm-basic-multiple-signatures-2.3.4-5.el9.noarch.rpm"
)

RPMS_V4 = os.path.join(ASSETS, "RPMS/v4")
RPM_V4_BASIC = os.path.join(RPMS_V4, "rpm-basic-2.3.4-5.el9.noarch.rpm")
RPM_V4_SIGNED = os.path.join(
    RPMS_V4, "signed/rpm-basic-with-rsa4096-2.3.4-5.el9.noarch.rpm"
)

SRPM_BASIC = os.path.join(SRPMS, "rpm-basic-2.3.4-5.el9.src.rpm")

# --- Signing key paths ---

KEYS = os.path.join(ASSETS, "signing_keys")

PUBLIC_KEY = os.path.join(KEYS, "v6/rpm-testkey-v6-rsa4k.asc")
PRIVATE_KEY = os.path.join(KEYS, "v6/rpm-testkey-v6-rsa4k.secret")
V4_PUBLIC_KEY = os.path.join(KEYS, "v4/rpm-testkey-v4-rsa4096.asc")
KEYRING_PRIVATE = os.path.join(KEYS, "v6/rpm-testkey-v6-keyring.secret")
OTHER_PUBLIC_KEY = os.path.join(KEYS, "v6/rpm-testkey-v6-ed25519.asc")

# Passphrase-protected key (v4 only — no v6 equivalent in test assets)
PROTECTED_PRIVATE_KEY = os.path.join(KEYS, "v4/rpm-testkey-v4-rsa3072-protected.secret")
PROTECTED_PUBLIC_KEY = os.path.join(KEYS, "v4/rpm-testkey-v4-rsa3072-protected.asc")
KEY_PASSPHRASE = "thisisN0Tasecuredpassphrase"
