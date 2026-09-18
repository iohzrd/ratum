//! The `wire_codes!` macro: an enum over the codes one wire field takes, with an `Unknown(code)`
//! variant, so a code this build does not name still survives a decode and an encode unchanged.

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
            pub fn code(self) -> $repr {
                match self {
                    $($name::$variant => $code,)*
                    $name::$unknown(code) => code,
                }
            }

            pub fn from_code(code: $repr) -> Self {
                match code {
                    $($code => $name::$variant,)*
                    other => $name::$unknown(other),
                }
            }
        }
    };
}

pub(crate) use wire_codes;
