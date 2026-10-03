#![allow(dead_code)]

pub const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");
pub const CARGO_OUT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target");

/// SOURCE_DATE_EPOCH used for building fixture packages (from build_packages.sh)
/// This timestamp is April 9, 2023 19:29:19 UTC
pub const FIXTURE_SOURCE_DATE: u32 = 1681068559;

pub mod pkgs {
    pub mod v4 {
        pub const RPM_EMPTY: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v4/rpm-empty-0-0.x86_64.rpm"
        );
        pub const RPM_BASIC: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v4/rpm-basic-2.3.4-5.el9.noarch.rpm"
        );
        pub const RPM_BASIC_RSA_SIGNED: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v4/signed/rpm-basic-with-rsa4096-2.3.4-5.el9.noarch.rpm"
        );
        pub const RPM_BASIC_ECDSA_SIGNED: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v4/signed/rpm-basic-with-ecdsa-2.3.4-5.el9.noarch.rpm"
        );
        pub const RPM_BASIC_EDDSA_SIGNED: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v4/signed/rpm-basic-with-ed25519-2.3.4-5.el9.noarch.rpm"
        );
        pub const RPM_BASIC_IMA_SIGNED: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v4/signed/rpm-basic-with-ima-2.3.4-5.el9.noarch.rpm"
        );

        pub mod src {
            pub const RPM_EMPTY_SRC: &str = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/SRPMS/v4/rpm-empty-0-0.src.rpm"
            );
            pub const RPM_BASIC_SRC: &str = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/SRPMS/v4/rpm-basic-2.3.4-5.el9.src.rpm"
            );
        }
    }

    pub mod v6 {
        pub const RPM_EMPTY: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v6/rpm-empty-0-0.x86_64.rpm"
        );
        pub const RPM_BASIC: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v6/rpm-basic-2.3.4-5.el9.noarch.rpm"
        );
        pub const RPM_FILE_ATTRS: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v6/rpm-file-attrs-1.0-1.noarch.rpm"
        );
        pub const RPM_FILE_TYPES: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v6/rpm-file-types-1.0-1.noarch.rpm"
        );
        pub const RPM_SPECIAL_FILES: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v6/rpm-special-files-1.0-1.noarch.rpm"
        );
        pub const RPM_HARDLINKS: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v6/rpm-hardlinks-1.0-1.noarch.rpm"
        );
        pub const RPM_I18N: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v6/rpm-i18n-1.0-1.noarch.rpm"
        );
        pub const RPM_RICH_DEPS: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v6/rpm-rich-deps-1.0-1.noarch.rpm"
        );
        pub const RPM_SCRIPTLETS: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v6/rpm-scriptlets-1.0-1.noarch.rpm"
        );
        pub const RPM_WITH_PATCH: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v6/rpm-with-patch-1.0-0.noarch.rpm"
        );

        pub const RPM_BASIC_RSA_SIGNED: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v6/signed/rpm-basic-with-rsa4k-2.3.4-5.el9.noarch.rpm"
        );
        pub const RPM_BASIC_EDDSA_SIGNED: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v6/signed/rpm-basic-with-ed25519-2.3.4-5.el9.noarch.rpm"
        );
        pub const RPM_BASIC_MLDSA_SIGNED: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v6/signed/rpm-basic-with-mldsa65-ed25519-2.3.4-5.el9.noarch.rpm"
        );
        pub const RPM_BASIC_MULTI_SIGNED: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/RPMS/v6/signed/rpm-basic-multiple-signatures-2.3.4-5.el9.noarch.rpm"
        );

        pub mod compressed {
            pub const RPM_BASIC_GZIP: &str = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/RPMS/v6/gzip/rpm-basic-2.3.4-5.el9.noarch.rpm"
            );
            pub const RPM_BASIC_ZSTD: &str = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/RPMS/v6/zstd/rpm-basic-2.3.4-5.el9.noarch.rpm"
            );
            pub const RPM_BASIC_XZ: &str = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/RPMS/v6/xz/rpm-basic-2.3.4-5.el9.noarch.rpm"
            );
        }

        pub mod src {
            pub const RPM_EMPTY_SRC: &str = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/SRPMS/v6/rpm-empty-0-0.src.rpm"
            );
            pub const RPM_BASIC_SRC: &str = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/SRPMS/v6/rpm-basic-2.3.4-5.el9.src.rpm"
            );
            pub const RPM_FILE_ATTRS_SRC: &str = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/SRPMS/v6/rpm-file-attrs-1.0-1.src.rpm"
            );
            pub const RPM_FILE_TYPES_SRC: &str = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/SRPMS/v6/rpm-file-types-1.0-1.src.rpm"
            );
            pub const RPM_HARDLINKS_SRC: &str = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/SRPMS/v6/rpm-hardlinks-1.0-1.src.rpm"
            );
        }
    }
}

pub mod keys {
    pub const IMA_SIGNING_KEY: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/assets/signing_keys/ima_signing.pem"
    );
    pub const IMA_SIGNING_KEY_PASSPHRASE: &str = "i_am_a_ima_signing_key";

    pub mod v4 {
        pub const RSA_4K_PUBLIC: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signing_keys/v4/rpm-testkey-v4-rsa4096.asc"
        );
        pub const RSA_4K_PRIVATE: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signing_keys/v4/rpm-testkey-v4-rsa4096.secret"
        );
        pub const RSA_3K_PROTECTED_PUBLIC: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signing_keys/v4/rpm-testkey-v4-rsa3072-protected.asc"
        );
        pub const RSA_3K_PROTECTED_PRIVATE: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signing_keys/v4/rpm-testkey-v4-rsa3072-protected.secret"
        );
        pub const RSA_3K_PASSPHRASE: &str = "thisisN0Tasecuredpassphrase";

        pub const ED25519_PUBLIC: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signing_keys/v4/rpm-testkey-v4-ed25519.asc"
        );
        pub const ED25519_PRIVATE: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signing_keys/v4/rpm-testkey-v4-ed25519.secret"
        );
        pub const ECDSA_NISTP256_PUBLIC: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signing_keys/v4/rpm-testkey-v4-ecdsa-nistp256.asc"
        );
        pub const ECDSA_NISTP256_PRIVATE: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signing_keys/v4/rpm-testkey-v4-ecdsa-nistp256.secret"
        );

        pub const KEYRING_PUBLIC: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signing_keys/v4/rpm-testkey-v4-keyring.asc"
        );
        pub const KEYRING_PRIVATE: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signing_keys/v4/rpm-testkey-v4-keyring.secret"
        );
    }

    pub mod v6 {
        pub const RSA_4K_PUBLIC: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signing_keys/v6/rpm-testkey-v6-rsa4k.asc"
        );
        pub const RSA_4K_PRIVATE: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signing_keys/v6/rpm-testkey-v6-rsa4k.secret"
        );

        pub const ED25519_PUBLIC: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signing_keys/v6/rpm-testkey-v6-ed25519.asc"
        );
        pub const ED25519_PRIVATE: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signing_keys/v6/rpm-testkey-v6-ed25519.secret"
        );

        pub const MLDSA65_ED25519_PUBLIC: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signing_keys/v6/rpm-testkey-v6-mldsa65-ed25519.asc"
        );
        pub const MLDSA65_ED25519_PRIVATE: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signing_keys/v6/rpm-testkey-v6-mldsa65-ed25519.secret"
        );

        pub const KEYRING_PUBLIC: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signing_keys/v6/rpm-testkey-v6-keyring.asc"
        );
        pub const KEYRING_PRIVATE: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signing_keys/v6/rpm-testkey-v6-keyring.secret"
        );
    }
}
