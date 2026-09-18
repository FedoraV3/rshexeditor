use anyhow::Result;

pub enum BinaryFormat {
    Pe,
    Elf,
}

pub fn get_file_type(bytes: &Vec<u8>) -> Result<BinaryFormat> {
    // we try to find each of the PE and elf

    Ok(BinaryFormat::Pe)
}
