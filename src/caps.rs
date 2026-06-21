//! Capability loading for the client side.
//!
//! ce-pin does not mint trust — it presents a signed, attenuating `ce-cap` chain that the host
//! authorizes. The chain is produced out-of-band (e.g. `ce grant <holder> --can pin:store …` on the
//! host or an org root, then handed to the publisher's wallet). For the MVP the client reads the
//! hex-encoded chain from, in order:
//!   1. the explicit `--caps <hex>` flag (highest precedence);
//!   2. the `$CE_PIN_CAPS` environment variable;
//!   3. `<config dir>/ce-pin/caps` (a file containing the hex chain).
//!
//! An empty/absent chain is allowed only when the target host roots at *itself* and self-issues —
//! but since the publisher is normally not the host, in practice a chain is required. We return an
//! empty string when none is configured and let the host's `authorize` reject it, surfacing a clear
//! "denied" rather than guessing.

use std::path::PathBuf;

/// Resolve the capability chain hex the client should present. `explicit` is the `--caps` flag.
pub fn resolve(explicit: Option<&str>) -> String {
    if let Some(c) = explicit.map(str::trim).filter(|c| !c.is_empty()) {
        return c.to_string();
    }
    if let Ok(c) = std::env::var("CE_PIN_CAPS") {
        let c = c.trim().to_string();
        if !c.is_empty() {
            return c;
        }
    }
    if let Some(p) = caps_file() {
        if let Ok(c) = std::fs::read_to_string(&p) {
            let c = c.trim().to_string();
            if !c.is_empty() {
                return c;
            }
        }
    }
    String::new()
}

fn caps_file() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("CE_PIN_DIR") {
        return Some(PathBuf::from(d).join("caps"));
    }
    directories::ProjectDirs::from("", "", "ce-pin").map(|p| p.config_dir().join("caps"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_takes_precedence() {
        assert_eq!(resolve(Some("deadbeef")), "deadbeef");
        assert_eq!(resolve(Some("  abc  ")), "abc");
    }

    #[test]
    fn empty_explicit_falls_through_to_none_when_unset() {
        // Use a unique env key isolation: ensure CE_PIN_CAPS unset for this assertion.
        unsafe {
            std::env::remove_var("CE_PIN_CAPS");
            std::env::set_var("CE_PIN_DIR", "/nonexistent-ce-pin-dir-xyz");
        }
        assert_eq!(resolve(Some("  ")), "");
        unsafe {
            std::env::remove_var("CE_PIN_DIR");
        }
    }
}
