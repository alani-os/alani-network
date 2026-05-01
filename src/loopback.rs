//! `loopback` module boundary.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoopbackDescriptor<'a> {
    pub name: &'a str,
    pub version: u32,
}

impl<'a> LoopbackDescriptor<'a> {
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}
