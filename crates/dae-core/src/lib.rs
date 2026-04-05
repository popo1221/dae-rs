//! dae-core library

pub mod engine;

pub use engine::Engine;

pub mod prelude {
    pub use crate::Engine;
}
