//! Primary build-artifact producers for registered board compositions.
//!
//! [`BoardDesc`](crate::board_desc::BoardDesc) owns runtime identity and
//! enablement policy. This inventory binds each declared artifact lane to the
//! build target that produces it and to the exact published basename. Keeping
//! that mapping typed prevents operator tools from reconstructing filenames
//! from product aliases.

/// Operator workflow attached to a published primary artifact.
///
/// This is intentionally more specific than the storage/update mechanism in
/// [`BoardDesc`](crate::board_desc::BoardDesc). AM1 and AM2 both use Zynq UBI
/// slot selection, but only AM1 has a managed first-install lane; AM2 remains a
/// restore-verified, already-running-DCENT_OS self-update contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactInstallContract {
    /// Managed signed-package install for the AM1/S9 lane.
    ManagedS9Install,
    /// Guarded AM2 inactive-slot self-update; not vendor-source first install.
    GuardedAm2SelfUpdate,
    /// Guarded host-written Amlogic rootfs-window workflow.
    GuardedAmlogicRootfsWindow,
    /// Host-buildable package whose hardware installation is explicitly denied.
    PackageOnlyDenied,
    /// Physical external-media payload; never a `dcent install` package.
    ExternalMedia,
}

impl ArtifactInstallContract {
    /// Stable wire value used by shell/operator tooling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ManagedS9Install => "managed_s9_install",
            Self::GuardedAm2SelfUpdate => "guarded_am2_self_update",
            Self::GuardedAmlogicRootfsWindow => "guarded_amlogic_rootfs_window",
            Self::PackageOnlyDenied => "package_only_denied",
            Self::ExternalMedia => "external_media",
        }
    }
}

/// One canonical build lane for a registered board target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrimaryArtifactProducer {
    /// Canonical [`BoardDesc`](crate::board_desc::BoardDesc) target.
    pub board_target: &'static str,
    /// Public target accepted by `scripts/build_in_docker.sh`.
    pub build_target: &'static str,
    /// Buildroot defconfig selected by the build target.
    pub defconfig: &'static str,
    /// Board overlay relative to `br2_external_dcentos`.
    pub overlay: &'static str,
    /// Whether the build driver runs the package-only validation lane.
    pub package_validated: bool,
    /// Exact basename published below `output/`.
    pub artifact_filename: &'static str,
    /// Exact operator workflow the artifact may enter.
    pub install_contract: ArtifactInstallContract,
}

/// Complete primary-producer inventory for every registered artifact claim.
pub const PRIMARY_ARTIFACT_PRODUCERS: &[PrimaryArtifactProducer] = &[
    PrimaryArtifactProducer {
        board_target: "am1-s9",
        build_target: "s9",
        defconfig: "dcentos_s9_defconfig",
        overlay: "board/zynq",
        package_validated: true,
        artifact_filename: "dcentos-unit.tar",
        install_contract: ArtifactInstallContract::ManagedS9Install,
    },
    PrimaryArtifactProducer {
        board_target: "am2-s19j",
        build_target: "am2-s19jpro",
        defconfig: "dcentos_am2_s19jpro_defconfig",
        overlay: "board/zynq/am2-s19jpro",
        package_validated: true,
        artifact_filename: "dcentos-sysupgrade-am2-s19jpro.tar",
        install_contract: ArtifactInstallContract::GuardedAm2SelfUpdate,
    },
    PrimaryArtifactProducer {
        board_target: "am2-s19pro",
        build_target: "am2-s19pro",
        defconfig: "dcentos_am2_s19pro_defconfig",
        overlay: "board/zynq/am2-s19pro",
        package_validated: true,
        artifact_filename: "dcentos-sysupgrade-am2-s19pro.tar",
        install_contract: ArtifactInstallContract::GuardedAm2SelfUpdate,
    },
    PrimaryArtifactProducer {
        board_target: "am2-s17p",
        build_target: "am2-s17pro",
        defconfig: "dcentos_am2_s17pro_zynq_defconfig",
        overlay: "board/zynq/am2-s17pro",
        package_validated: true,
        artifact_filename: "dcentos-sysupgrade-am2-s17pro.tar",
        install_contract: ArtifactInstallContract::PackageOnlyDenied,
    },
    PrimaryArtifactProducer {
        board_target: "am3-bb",
        build_target: "am3-bb",
        defconfig: "dcentos_am3_bb_defconfig",
        overlay: "board/beaglebone/am3-bb",
        package_validated: false,
        artifact_filename: "dcentos-am3-bb-sdcard.tar",
        install_contract: ArtifactInstallContract::ExternalMedia,
    },
    PrimaryArtifactProducer {
        board_target: "am3-bb-s19jpro",
        build_target: "am3-bb-s19jpro",
        defconfig: "dcentos_am3_bb_s19jpro_defconfig",
        overlay: "board/beaglebone/am3-bb-s19jpro",
        package_validated: false,
        artifact_filename: "dcentos-am3-bb-s19jpro-sdcard.tar",
        install_contract: ArtifactInstallContract::ExternalMedia,
    },
    PrimaryArtifactProducer {
        board_target: "am3-s21",
        build_target: "am3-s21",
        defconfig: "dcentos_am3_s21_defconfig",
        overlay: "board/amlogic/am3-s21",
        package_validated: true,
        artifact_filename: "dcentos-sysupgrade-am3-s21.tar",
        install_contract: ArtifactInstallContract::GuardedAmlogicRootfsWindow,
    },
    PrimaryArtifactProducer {
        board_target: "am3-s21pro",
        build_target: "am3-s21pro",
        defconfig: "dcentos_am3_s21pro_defconfig",
        overlay: "board/amlogic/am3-s21pro",
        package_validated: true,
        artifact_filename: "dcentos-sysupgrade-am3-s21pro.tar",
        install_contract: ArtifactInstallContract::GuardedAmlogicRootfsWindow,
    },
    PrimaryArtifactProducer {
        board_target: "am3-s21xp",
        build_target: "am3-s21xp",
        defconfig: "dcentos_am3_s21xp_defconfig",
        overlay: "board/amlogic/am3-s21xp",
        package_validated: true,
        artifact_filename: "dcentos-sysupgrade-am3-s21xp.tar",
        install_contract: ArtifactInstallContract::GuardedAmlogicRootfsWindow,
    },
    PrimaryArtifactProducer {
        board_target: "am3-t21",
        build_target: "am3-t21",
        defconfig: "dcentos_am3_t21_defconfig",
        overlay: "board/amlogic/am3-t21",
        package_validated: true,
        artifact_filename: "dcentos-sysupgrade-am3-t21.tar",
        install_contract: ArtifactInstallContract::GuardedAmlogicRootfsWindow,
    },
    PrimaryArtifactProducer {
        board_target: "am3-s19k",
        build_target: "am3-s19kpro",
        defconfig: "dcentos_am3_s19kpro_defconfig",
        overlay: "board/amlogic/am3-s19kpro",
        package_validated: true,
        artifact_filename: "dcentos-sysupgrade-am3-s19kpro.tar",
        install_contract: ArtifactInstallContract::GuardedAmlogicRootfsWindow,
    },
    PrimaryArtifactProducer {
        board_target: "am3-s19xp",
        build_target: "am3-s19xp",
        defconfig: "dcentos_am3_s19xp_defconfig",
        overlay: "board/amlogic/am3-s19xp",
        package_validated: true,
        artifact_filename: "dcentos-sysupgrade-am3-s19xp.tar",
        install_contract: ArtifactInstallContract::GuardedAmlogicRootfsWindow,
    },
    PrimaryArtifactProducer {
        board_target: "am3-s19jxp",
        build_target: "am3-s19jxp",
        defconfig: "dcentos_am3_s19jxp_defconfig",
        overlay: "board/amlogic/am3-s19jxp",
        package_validated: true,
        artifact_filename: "dcentos-sysupgrade-am3-s19jxp.tar",
        install_contract: ArtifactInstallContract::GuardedAmlogicRootfsWindow,
    },
    PrimaryArtifactProducer {
        board_target: "am3-s19jproplus",
        build_target: "am3-s19jproplus",
        defconfig: "dcentos_am3_s19jproplus_defconfig",
        overlay: "board/amlogic/am3-s19jproplus",
        package_validated: true,
        artifact_filename: "dcentos-sysupgrade-am3-s19jproplus.tar",
        install_contract: ArtifactInstallContract::GuardedAmlogicRootfsWindow,
    },
    PrimaryArtifactProducer {
        board_target: "am3-s19jpro-aml",
        build_target: "am3-s19jpro-aml",
        defconfig: "dcentos_am3_s19jpro_aml_defconfig",
        overlay: "board/amlogic/am3-s19jpro-aml",
        package_validated: true,
        artifact_filename: "dcentos-sysupgrade-am3-s19jpro-aml.tar",
        install_contract: ArtifactInstallContract::GuardedAmlogicRootfsWindow,
    },
];

/// Resolve one canonical board target to its primary artifact producer.
pub fn primary_artifact_producer(board_target: &str) -> Option<&'static PrimaryArtifactProducer> {
    PRIMARY_ARTIFACT_PRODUCERS
        .iter()
        .find(|producer| producer.board_target == board_target)
}

/// Stable, versioned producer manifest for non-Rust operator tooling.
pub fn artifact_producer_manifest_json() -> String {
    let mut out = String::from("{\n  \"schema\": 2,\n  \"producers\": [\n");
    for (index, producer) in PRIMARY_ARTIFACT_PRODUCERS.iter().enumerate() {
        if index != 0 {
            out.push_str(",\n");
        }
        out.push_str(&format!(
            concat!(
                "    {{\"board_target\":\"{}\",\"build_target\":\"{}\",",
                "\"artifact_filename\":\"{}\",\"install_contract\":\"{}\"}}"
            ),
            producer.board_target,
            producer.build_target,
            producer.artifact_filename,
            producer.install_contract.as_str(),
        ));
    }
    out.push_str("\n  ]\n}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_desc::{BoardDesc, BoardFamily};
    use dcent_schema::hardware::{ArtifactKind, UpdateMechanism};
    use std::collections::BTreeSet;

    #[test]
    fn producer_targets_are_unique_and_cover_every_artifact_claim() {
        let mut claimed: Vec<_> = BoardDesc::all_registered()
            .iter()
            .filter(|board| board.enablement.artifact_kind != ArtifactKind::None)
            .map(|board| board.board_target)
            .collect();
        let mut mapped: Vec<_> = PRIMARY_ARTIFACT_PRODUCERS
            .iter()
            .map(|producer| producer.board_target)
            .collect();
        claimed.sort_unstable();
        mapped.sort_unstable();
        assert_eq!(
            claimed, mapped,
            "artifact claims and primary build-producer inventory drifted"
        );
        assert_eq!(
            mapped.iter().copied().collect::<BTreeSet<_>>().len(),
            mapped.len(),
            "primary producer target is duplicated"
        );
    }

    #[test]
    fn published_filenames_are_safe_unique_basenames() {
        let mut filenames = BTreeSet::new();
        for producer in PRIMARY_ARTIFACT_PRODUCERS {
            assert!(!producer.artifact_filename.is_empty());
            assert!(!producer.artifact_filename.contains(['/', '\\']));
            assert!(!producer.artifact_filename.contains(".."));
            assert!(
                filenames.insert(producer.artifact_filename),
                "duplicate artifact filename {}",
                producer.artifact_filename
            );
        }
    }

    #[test]
    fn install_contracts_match_typed_board_topology() {
        for producer in PRIMARY_ARTIFACT_PRODUCERS {
            let board = BoardDesc::lookup(producer.board_target)
                .unwrap_or_else(|| panic!("missing descriptor {}", producer.board_target));
            match producer.install_contract {
                ArtifactInstallContract::ManagedS9Install => {
                    assert_eq!(producer.board_target, "am1-s9");
                    assert!(producer.package_validated);
                    assert_eq!(board.family, BoardFamily::Zynq);
                    assert_eq!(
                        board.enablement.update_mechanism,
                        UpdateMechanism::ZynqUbiFwSetenv
                    );
                    assert_eq!(
                        board.enablement.artifact_kind,
                        ArtifactKind::SysupgradeBundle
                    );
                }
                ArtifactInstallContract::GuardedAm2SelfUpdate => {
                    assert!(producer.board_target.starts_with("am2-"));
                    assert_eq!(board.family, BoardFamily::Zynq);
                    assert_eq!(
                        board.enablement.update_mechanism,
                        UpdateMechanism::ZynqUbiFwSetenv
                    );
                    assert_eq!(
                        board.enablement.artifact_kind,
                        ArtifactKind::SysupgradeBundle
                    );
                }
                ArtifactInstallContract::GuardedAmlogicRootfsWindow => {
                    assert_eq!(board.family, BoardFamily::Amlogic);
                    assert_eq!(
                        board.enablement.update_mechanism,
                        UpdateMechanism::HostRootfsWindow
                    );
                    assert_eq!(
                        board.enablement.artifact_kind,
                        ArtifactKind::SysupgradeBundle
                    );
                }
                ArtifactInstallContract::PackageOnlyDenied => {
                    assert_eq!(
                        board.enablement.artifact_kind,
                        ArtifactKind::SysupgradeBundle
                    );
                    assert_eq!(
                        board.enablement.install_authorization,
                        dcent_schema::hardware::InstallAuthorization::Denied
                    );
                    match board.family {
                        BoardFamily::Amlogic => assert_eq!(
                            board.enablement.update_mechanism,
                            UpdateMechanism::HostRootfsWindow
                        ),
                        BoardFamily::Zynq => {
                            assert_eq!(producer.board_target, "am2-s17p");
                            assert_eq!(
                                board.enablement.update_mechanism,
                                UpdateMechanism::ZynqUbiFwSetenv
                            );
                        }
                        family => panic!(
                            "unexpected package-only family {family:?} for {}",
                            producer.board_target
                        ),
                    }
                }
                ArtifactInstallContract::ExternalMedia => {
                    assert!(!producer.package_validated);
                    assert_eq!(board.family, BoardFamily::BeagleBone);
                    assert_eq!(board.enablement.update_mechanism, UpdateMechanism::SdImage);
                    assert_eq!(board.enablement.artifact_kind, ArtifactKind::SdCardPayload);
                }
            }
        }
    }

    #[test]
    fn committed_manifest_matches_typed_inventory() {
        let committed = include_str!("../../../docs/architecture/artifact_producers.json");
        assert_eq!(
            committed.replace("\r\n", "\n"),
            artifact_producer_manifest_json(),
            "artifact_producers.json drifted from the typed producer inventory"
        );
    }

    #[test]
    fn sysupgrade_producers_emit_their_published_filename_in_install_metadata() {
        let project_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("dcentrald-common lives under DCENT_OS_Antminer/dcentrald");
        let s9_packager = include_str!("../../../scripts/package_sysupgrade.sh");
        assert!(
            s9_packager.contains("ARTIFACT_FILENAME=${OUTPUT_FILE##*/}"),
            "S9 packager must derive metadata from its actual output basename"
        );
        assert!(
            !s9_packager.contains("am2-s19j"),
            "S9 packager must not duplicate the dedicated AM2 artifact producer"
        );
        assert_eq!(
            s9_packager
                .matches(r#""install_command": "dcent install <ip> -f $ARTIFACT_FILENAME""#)
                .count(),
            2,
            "both signed and unsigned S9 manifests must use the actual output basename"
        );

        let common_helper = include_str!("../../../scripts/lib/sysupgrade_package_common.sh");
        assert!(
            common_helper.contains("dcent_require_toolbox_install_contract"),
            "shared package helper must validate operator-command safety"
        );
        assert!(
            common_helper.contains(
                "dcent_require_toolbox_install_contract \"$install_command\" \"$install_mode\""
            ),
            "manifest writer must invoke the operator-command safety gate"
        );

        for producer in PRIMARY_ARTIFACT_PRODUCERS {
            let board = BoardDesc::lookup(producer.board_target)
                .unwrap_or_else(|| panic!("missing descriptor {}", producer.board_target));
            if board.enablement.artifact_kind != ArtifactKind::SysupgradeBundle
                || producer.board_target == "am1-s9"
            {
                continue;
            }
            let post_image = project_root
                .join("br2_external_dcentos")
                .join(producer.overlay)
                .join("post-image.sh");
            let source = std::fs::read_to_string(&post_image)
                .unwrap_or_else(|error| panic!("read {}: {error}", post_image.display()));
            let shared_amlogic =
                include_str!("../../../br2_external_dcentos/board/amlogic/am3-s21/post-image.sh");
            let metadata_source = if producer.install_contract
                == ArtifactInstallContract::GuardedAmlogicRootfsWindow
                && source.lines().any(|line| {
                    line.trim_start().starts_with("exec ") && line.contains("am3-s21/post-image.sh")
                }) {
                shared_amlogic
            } else {
                source.as_str()
            };
            if producer.install_contract == ArtifactInstallContract::PackageOnlyDenied {
                let denial_source = if board.family == BoardFamily::Amlogic {
                    assert!(
                        source.contains("am3-s21/post-image.sh"),
                        "{} must delegate to the shared A113D packager",
                        producer.board_target
                    );
                    shared_amlogic
                } else {
                    source.as_str()
                };
                assert!(denial_source.contains("DCENT_TOOLBOX_INSTALL_MODE=package_only_denied"));
                assert!(denial_source.contains("DCENT_PACKAGE_INSTALLABLE=false"));
                assert!(denial_source.contains("DCENT_TOOLBOX_INSTALL_COMMAND="));
                assert!(denial_source.contains("DCENT_TOOLBOX_UPDATE_COMMAND="));
                continue;
            }
            let required_args = match producer.install_contract {
                ArtifactInstallContract::GuardedAm2SelfUpdate => concat!(
                    " --artifact-dir <restore_verified_dir>",
                    " --accept-am2-persistent-lab --i-have-recovery"
                ),
                ArtifactInstallContract::GuardedAmlogicRootfsWindow => {
                    " --artifact-dir <restore_verified_dir>"
                }
                ArtifactInstallContract::ManagedS9Install
                | ArtifactInstallContract::ExternalMedia
                | ArtifactInstallContract::PackageOnlyDenied => {
                    panic!(
                        "unexpected sysupgrade post-image contract for {}",
                        producer.board_target
                    )
                }
            };
            let expected = format!(
                "DCENT_TOOLBOX_INSTALL_COMMAND=\"dcent install <ip> -f {}{}\"",
                producer.artifact_filename, required_args
            );
            let actual = metadata_source
                .lines()
                .map(str::trim_start)
                .find(|line| line.starts_with("DCENT_TOOLBOX_INSTALL_COMMAND="))
                .unwrap_or_else(|| {
                    panic!(
                        "{} post-image omits DCENT_TOOLBOX_INSTALL_COMMAND",
                        producer.board_target
                    )
                });
            let shared_dynamic = matches!(
                producer.board_target,
                "am3-s21" | "am3-s19xp" | "am3-s19jxp" | "am3-s19jproplus"
            )
                && actual
                    == "DCENT_TOOLBOX_INSTALL_COMMAND=\"dcent install <ip> -f ${OUTPUT_BASENAME} --artifact-dir <restore_verified_dir>\"";
            assert!(
                actual == expected || shared_dynamic,
                "{} install metadata does not encode its exact operator contract: {}",
                producer.board_target,
                actual
            );
            assert!(
                !actual.contains(" --yes"),
                "{} install metadata must preserve interactive confirmation",
                producer.board_target
            );
            assert!(
                !actual.contains("--accept-vnish-aml-rootfs-window"),
                "{} package metadata must not pre-acknowledge a source-specific gate",
                producer.board_target
            );
        }
    }
}
