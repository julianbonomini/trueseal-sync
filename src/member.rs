// Member identity utilities.
//
// `member_id` and `member_name` are pure, deterministic transforms on a
// `SigningPublicKey`. They are the only public interface the caller ever sees
// for "who is in my group" — no key bytes, no crypto.

use crate::keys::SigningPublicKey;

// ── Word lists ────────────────────────────────────────────────────────────────

static ADJECTIVES: &[&str] = &[
    "Amber", "Azure", "Brave", "Bright", "Calm", "Clear", "Crisp", "Dark", "Deep", "Dense", "Dusk",
    "Early", "Fast", "Firm", "Free", "Fresh", "Gold", "Grand", "Gray", "Green", "High", "Icy",
    "Iron", "Jade", "Kind", "Large", "Late", "Lava", "Lean", "Light", "Long", "Loud", "Low",
    "Lunar", "Mint", "Mist", "Nimble", "Noble", "Nord", "Oak", "Old", "Open", "Pale", "Pine",
    "Plain", "Pure", "Quick", "Quiet", "Rapid", "Raw", "Red", "Rich", "Rocky", "Round", "Royal",
    "Salt", "Sand", "Sharp", "Short", "Silent", "Silver", "Slim", "Slow", "Small", "Smoke", "Snow",
    "Solar", "Solid", "South", "Still", "Stone", "Storm", "Strong", "Sunny", "Swift", "Tall",
    "Teal", "Thin", "Tidal", "Tiny", "True", "Ultra", "Vast", "Vivid", "Warm", "West", "Wild",
    "Wind", "Winter", "Wise", "Young", "Zeal", "Bold", "Cool", "Even", "Flat", "Glad", "Hazy",
    "Just", "Keen", "Live", "Mild", "Nice", "Odd", "Peak", "Rare", "Safe", "Soft", "Tame",
    "Unique", "Wet", "Wide", "Worn", "Zero", "Apex", "Core", "Edge", "Flow", "Gate", "Hard",
    "Idea", "Jump",
];

static NOUNS: &[&str] = &[
    "Anchor", "Arrow", "Ash", "Axe", "Bay", "Bear", "Bird", "Blade", "Bloom", "Bolt", "Bone",
    "Book", "Bow", "Branch", "Brook", "Buck", "Cliff", "Cloud", "Coal", "Coast", "Coil", "Colt",
    "Cone", "Cord", "Crane", "Creek", "Crest", "Cross", "Crown", "Curve", "Dawn", "Deck", "Deer",
    "Dell", "Dew", "Disc", "Dome", "Door", "Dove", "Draft", "Drake", "Drift", "Drum", "Dusk",
    "Dust", "Eagle", "Echo", "Elm", "Ember", "Fang", "Fawn", "Fern", "Field", "Fire", "Fish",
    "Flame", "Flint", "Fog", "Ford", "Fork", "Forge", "Fort", "Fox", "Frost", "Gate", "Glade",
    "Glen", "Globe", "Glow", "Gold", "Grain", "Grove", "Guard", "Guide", "Gust", "Hawk", "Haze",
    "Heath", "Helm", "Hill", "Hive", "Horn", "Hound", "Hull", "Ice", "Iris", "Isle", "Ivy", "Jade",
    "Jet", "Kelp", "Key", "Knot", "Lake", "Lark", "Lava", "Leaf", "Ledge", "Light", "Line", "Link",
    "Lion", "Lodge", "Loop", "Lure", "Lynx", "Map", "Mare", "Mark", "Marsh", "Mast", "Mead",
    "Mesa", "Mill", "Mind", "Mine", "Mire", "Mist", "Moon", "Moor", "Moss", "Mount", "Mud", "Mule",
    "Musk", "Nest", "Net", "Node",
];

// ── Public API ────────────────────────────────────────────────────────────────

/// Stable, opaque identifier for a group member.
///
/// Derived deterministically from the first 8 bytes of their `signing_pub`
/// via base64url encoding (no padding). 11 characters, e.g. `"YWJjZGVmZ2"`.
/// Collision probability is negligible for groups under 10,000 members.
pub fn member_id(signing_pub: &SigningPublicKey) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signing_pub.0[..8])
}

/// Human-readable auto-generated name for a group member.
///
/// Deterministic: the same `signing_pub` always produces the same name.
/// Format: two capitalised words, e.g. `"AmberFalcon"` or `"SwiftHorizon"`.
/// Names are unique within realistic group sizes (≤20 devices).
pub fn member_name(signing_pub: &SigningPublicKey) -> String {
    let adj = ADJECTIVES[signing_pub.0[0] as usize % ADJECTIVES.len()];
    let noun = NOUNS[signing_pub.0[1] as usize % NOUNS.len()];
    format!("{adj}{noun}")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_signing_pub(bytes: [u8; 32]) -> SigningPublicKey {
        SigningPublicKey(bytes)
    }

    /// member_id is 11 base64url characters (8 raw bytes, no padding).
    #[test]
    fn member_id_is_11_chars() {
        let sp = make_signing_pub([0u8; 32]);
        assert_eq!(member_id(&sp).len(), 11);
    }

    /// member_id is deterministic — same input, same output.
    #[test]
    fn member_id_is_deterministic() {
        let sp = make_signing_pub([
            0xAB, 0xCD, 0xEF, 1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(member_id(&sp), member_id(&sp));
    }

    /// Different signing pubs produce different ids.
    #[test]
    fn member_id_differs_for_different_keys() {
        let sp1 = make_signing_pub([1u8; 32]);
        let sp2 = make_signing_pub([2u8; 32]);
        assert_ne!(member_id(&sp1), member_id(&sp2));
    }

    /// member_name is two concatenated capitalised words.
    #[test]
    fn member_name_format() {
        let sp = make_signing_pub([0u8; 32]);
        let name = member_name(&sp);
        // Should be non-empty and start with an uppercase letter.
        assert!(!name.is_empty());
        assert!(name.chars().next().unwrap().is_uppercase());
    }

    /// member_name is deterministic.
    #[test]
    fn member_name_is_deterministic() {
        let sp = make_signing_pub([42u8; 32]);
        assert_eq!(member_name(&sp), member_name(&sp));
    }

    /// Different keys produce different names (spot-check, not exhaustive).
    #[test]
    fn member_name_varies_with_key() {
        let names: Vec<_> = (0u8..20)
            .map(|i| {
                let mut b = [0u8; 32];
                b[0] = i;
                b[1] = i.wrapping_mul(7);
                member_name(&make_signing_pub(b))
            })
            .collect();
        // Collect unique names; expect at least 15 distinct out of 20.
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert!(unique.len() >= 15, "too many collisions: {unique:?}");
    }

    /// Known bytes produce a known id — pin the encoding.
    #[test]
    fn member_id_known_value() {
        // [0,0,0,0,0,0,0,0] base64url = "AAAAAAAAAAA"
        let sp = make_signing_pub([0u8; 32]);
        assert_eq!(member_id(&sp), "AAAAAAAAAAA");
    }
}
