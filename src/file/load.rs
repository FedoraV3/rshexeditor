use anyhow::Result;

use std::fs::read;
use std::path::PathBuf;

pub enum BinaryFormat {
    Pe,
    Elf
}

pub struct Sh0k0h3xFile {
    pub file_buffer: Vec<u8>,
    file_type: BinaryFormat,
    // planning to remove this later if i never see it being used
    file_name: String,
    file_size: usize,
}


pub fn load_file_raw_bytes(path: &PathBuf) -> Result<Sh0k0h3xFile> {
    todo!()
}