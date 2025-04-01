use thiserror::Error;

pub mod committee;
pub mod community;
pub mod crypto;
pub mod network;

#[derive(Debug)]
#[derive(Error)]
pub enum MockError{}
