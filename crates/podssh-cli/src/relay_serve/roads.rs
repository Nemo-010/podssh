//! `--relay-roads WORDS` of `podssh relay serve` (T-720): the meeting points
//! of a net on the role's one listener, `iroh` (iroh's relay protocol at
//! `/relay`, `podssh_relay::serve::meet`'s) and `derp` (DERP at `/derp`,
//! `relay_serve/derp.rs`'s), each with the probes `/ping` and
//! `/generate_204`. Whom each admits follows the role's other flags: iroh's
//! endpoints as `--mint` admits a key (an endpoint's key is a key of
//! podssh's identity); DERP's node keys by `--derp-keys FILE`, or each one
//! where the role mints for anyone, as derper with no `--verify-clients`.
//! A road that would admit nobody stops the start. No listener of its own.

use podssh_relay::serve::Mint;

use super::derp;
use crate::relay_settings::Refusal;

/// The roads that `--relay-roads` named.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Roads {
    pub iroh: bool,
    pub derp: bool,
}

/// The roads of `words`: `iroh`, `derp`, or both, separated by commas.
pub(super) fn parse(words: Option<&str>) -> Result<Roads, Refusal> {
    let mut roads = Roads::default();
    let Some(words) = words else { return Ok(roads) };
    for word in words.split(',').map(str::trim) {
        match word {
            "iroh" => roads.iroh = true,
            "derp" => roads.derp = true,
            _ => return Err(Refusal::usage(format!("--relay-roads {words:?}: iroh, derp, or iroh,derp"))),
        }
    }
    Ok(roads)
}

/// The roads turned on: the words of the start's line, empty with none.
/// `--derp-keys FILE` alone turns DERP on, as before (T-106).
pub(super) fn of(words: Option<&str>, derp_keys: Option<&str>, mint: &Mint) -> Result<String, Refusal> {
    let roads = parse(words)?;
    let mut shown = String::new();
    if roads.derp || derp_keys.is_some() {
        shown.push_str(&derp_of(derp_keys, mint)?);
    }
    if roads.iroh {
        shown.push_str(&iroh(mint)?);
    }
    Ok(shown)
}

/// DERP for the keys of a file, or for each key where the role mints for
/// anyone.
fn derp_of(keys: Option<&str>, mint: &Mint) -> Result<String, Refusal> {
    if keys.is_some() {
        return derp::of(keys);
    }
    if !matches!(mint, Mint::Anyone) {
        let why = "--relay-roads derp: name the node keys that it admits with --derp-keys FILE. \
                   With --mint anyone, it admits each key.";
        return Err(Refusal::usage(why));
    }
    podssh_relay::serve::derp::enable_open();
    Ok(", DERP at /derp for each node key (--mint anyone), with /generate_204".into())
}

/// iroh's relay protocol, for the endpoints that `--mint` admits.
#[cfg(feature = "iroh")]
fn iroh(mint: &Mint) -> Result<String, Refusal> {
    if matches!(mint, Mint::Nobody) {
        let why = "--relay-roads iroh admits the keys that --mint admits, and --mint nobody admits none. \
                   Give --mint anyone, keys:FILE or net.";
        return Err(Refusal::usage(why));
    }
    podssh_relay::serve::meet::enable_iroh();
    Ok(format!(", iroh's relay protocol at /relay for the endpoints of --mint {}, with /ping", mint.word()))
}

/// No iroh road in this build: refused with exit 70, as an iroh destination.
#[cfg(not(feature = "iroh"))]
fn iroh(_: &Mint) -> Result<String, Refusal> {
    Err(Refusal {
        message: "--relay-roads iroh: the iroh road is not in this build; build podssh with --features iroh \
                  (cargo build -p podssh-cli --features iroh)"
            .into(),
        code: crate::exit_codes::EXIT_NOT_IMPLEMENTED,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_words_are_iroh_derp_or_both() {
        assert_eq!(parse(None).unwrap(), Roads::default());
        assert_eq!(parse(Some("iroh")).unwrap(), Roads { iroh: true, derp: false });
        assert_eq!(parse(Some("derp")).unwrap(), Roads { iroh: false, derp: true });
        assert_eq!(parse(Some("iroh, derp")).unwrap(), Roads { iroh: true, derp: true });
        for bad in ["", "tailscale", "iroh,,derp", "IROH"] {
            let refused = parse(Some(bad)).expect_err(bad);
            assert_eq!(refused.code, crate::exit_codes::EXIT_USAGE, "{bad}");
            assert!(refused.message.contains("iroh, derp, or iroh,derp"), "{bad}: {}", refused.message);
        }
    }

    #[test]
    fn derp_with_no_file_admits_nobody_unless_the_role_mints_for_anyone() {
        let refused = of(Some("derp"), None, &Mint::Nobody).expect_err("no file, no mint for anyone");
        assert!(refused.message.contains("--derp-keys FILE"), "{}", refused.message);
        assert_eq!(of(None, None, &Mint::Nobody).unwrap(), "", "no road named, none on");
    }

    #[cfg(feature = "iroh")]
    #[test]
    fn iroh_with_a_mint_for_nobody_admits_nobody_and_stops_the_start() {
        let refused = of(Some("iroh"), None, &Mint::Nobody).expect_err("nobody");
        assert_eq!(refused.code, crate::exit_codes::EXIT_USAGE);
        assert!(refused.message.contains("--mint nobody admits none"), "{}", refused.message);
    }

    #[cfg(not(feature = "iroh"))]
    #[test]
    fn iroh_in_a_build_with_no_iroh_road_is_refused_with_70() {
        let refused = of(Some("iroh"), None, &Mint::Anyone).expect_err("no iroh road");
        assert_eq!(refused.code, crate::exit_codes::EXIT_NOT_IMPLEMENTED);
        assert!(refused.message.contains("--features iroh"), "{}", refused.message);
    }
}
