//! Hedwig as a library: the module tree lives here so the server binary,
//! unit tests, and the fuzz targets (`fuzz/`) all link against one crate.

use subtle::ConstantTimeEq;

pub mod callbacks;
pub mod config;
pub mod dkim;
pub mod health;
pub mod logqueue;
pub mod metrics;
pub mod migrate;
pub mod mta_sts;
pub mod queue_cli;
pub mod storage;
pub mod worker;

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
