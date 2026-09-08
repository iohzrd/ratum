//! [`wire_codes`], which declares an enum whose variants stand for protocol codes.
//!
//! Both directions of the conversion are generated from the one list of `Variant = code`
//! pairs, so a variant added without a decode arm, or a decode arm naming a code no variant
//! carries, cannot be written.

/// Declare a wire-coded enum in either of two forms.
///
/// On its own the enum is `#[repr]`-tagged with its codes and the decode is partial:
/// `from_code` returns `None` for a code no variant names, which is what a message carrying
/// a reason this build does not name needs.
///
/// ```ignore
/// wire_codes! {
///     #[derive(Clone, Copy, Debug, PartialEq, Eq)]
///     pub enum RejectReason: u16 {
///         BadJobId = 10,
///         BadCoinbaseId = 11,
///     }
/// }
/// ```
///
/// Followed by `unknown <Variant>;`, that variant carries any other code verbatim and both
/// directions are total.
///
/// ```ignore
/// wire_codes! {
///     #[derive(Clone, Copy, Debug, PartialEq, Eq)]
///     pub enum Status: u8 {
///         Ok = 0x01,
///         JobEmpty = 0xF0,
///     }
///     /// A status byte not listed above.
///     unknown Unknown;
/// }
/// ```
macro_rules! wire_codes {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident: $repr:ty {
            $($(#[$vmeta:meta])* $variant:ident = $code:literal),* $(,)?
        }
        $(#[$umeta:meta])*
        unknown $unknown:ident;
    ) => {
        $(#[$meta])*
        $vis enum $name {
            $($(#[$vmeta])* $variant,)*
            $(#[$umeta])* $unknown($repr),
        }

        impl $name {
            /// The code this variant is sent as; for the catch-all, the one it carries.
            pub fn code(self) -> $repr {
                match self {
                    $($name::$variant => $code,)*
                    $name::$unknown(code) => code,
                }
            }

            /// The variant `code` names, or the catch-all carrying it.
            pub fn from_code(code: $repr) -> Self {
                match code {
                    $($code => $name::$variant,)*
                    other => $name::$unknown(other),
                }
            }
        }
    };

    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident: $repr:ty {
            $($(#[$vmeta:meta])* $variant:ident = $code:literal),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[repr($repr)]
        $vis enum $name {
            $($(#[$vmeta])* $variant = $code,)*
        }

        impl $name {
            /// The code this variant is sent as.
            pub fn code(self) -> $repr {
                self as $repr
            }

            /// The variant `code` names, or `None` when no variant names it.
            pub fn from_code(code: $repr) -> Option<Self> {
                Some(match code {
                    $($code => $name::$variant,)*
                    _ => return None,
                })
            }
        }
    };
}

pub(crate) use wire_codes;

#[cfg(test)]
mod tests {
    wire_codes! {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum Partial: u16 {
            First = 7,
            Second = 4000,
        }
    }

    wire_codes! {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum Total: u8 {
            Yes = 0x01,
            No = 0xF0,
        }
        /// A code not listed above.
        unknown Other;
    }

    #[test]
    fn a_partial_enum_decodes_only_the_codes_it_names() {
        assert_eq!(Partial::First.code(), 7);
        assert_eq!(Partial::Second.code(), 4000);
        assert_eq!(Partial::from_code(7), Some(Partial::First));
        assert_eq!(Partial::from_code(4000), Some(Partial::Second));
        assert_eq!(Partial::from_code(8), None);
    }

    #[test]
    fn a_total_enum_carries_a_code_it_does_not_name() {
        assert_eq!(Total::Yes.code(), 0x01);
        assert_eq!(Total::from_code(0xF0), Total::No);
        assert_eq!(Total::from_code(0x42), Total::Other(0x42));
        assert_eq!(Total::Other(0x42).code(), 0x42);
    }
}
