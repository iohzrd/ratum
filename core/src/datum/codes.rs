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
            pub fn code(self) -> $repr {
                self as $repr
            }

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
