use crate::iop::target::Target;

/// A named copy constraint.
pub struct CopyConstraint {
    pub pair: (Target, Target),

    #[cfg(any(feature = "log", test))]
    pub name: String,
}

impl From<(Target, Target)> for CopyConstraint {
    fn from(pair: (Target, Target)) -> Self {
        #[cfg(any(feature = "log", test))]
        {
            Self {
                pair,
                name: String::new(),
            }
        }

        #[cfg(not(any(feature = "log", test)))]
        {
            Self {
                pair,
            }
        }
    }
}

impl CopyConstraint {
    #[cfg(any(feature = "log", test))]
    pub fn new(pair: (Target, Target), name: String) -> Self {
        Self { pair, name }
    }

    #[cfg(not(any(feature = "log", test)))]
    pub fn new(pair: (Target, Target)) -> Self {
        Self { pair }
    }
}
