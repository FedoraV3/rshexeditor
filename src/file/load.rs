use anyhow::Result;

use std::fs::read;
use std::path::PathBuf;

use crate::checker::checker::{BinaryFormat, get_file_type};

pub struct Sh0k0h3xFile {
    pub file_buffer: Vec<u8>,
    pub file_type: BinaryFormat,
    // planning to remove this later if i never see it being used
    pub file_name: String,
    pub file_size: usize,
}

pub fn load_file_raw_bytes(path: &PathBuf) -> Result<Sh0k0h3xFile> {
    let file = read(&path)?;
    let f_bin_type = get_file_type(&file)?;

    let f_name;
    // get extra file information
    if let Some(path_str) = path.file_name() {
        f_name = path_str.to_string_lossy().into_owned();
    } else {
        // fallback
        f_name = String::from("Unknown File Name");
    }

    let f_size = file.len();

    Ok({
        Sh0k0h3xFile {
            file_buffer: file,
            file_type: f_bin_type,
            file_name: f_name,
            file_size: f_size,
        }
    })
}
