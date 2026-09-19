//! Binary file type detection and parsing.
//!
//! Currently targets the PE (Portable Executable) format used by Windows,
//! with ELF support planned. Layout constants below follow the Microsoft
//! PE format reference:
//! <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>
//!
//! ## PE layout, at a glance
//! - `0x00`: DOS header magic (`4D 5A`, i.e. `"MZ"`).
//! - `0x3C`: offset (a `u32`) of the NT / COFF header, relative to the start
//!   of the file. Read this to find where [`CoffFileHeaderOffset`] applies.

use anyhow::Result;

/// The binary container format detected for a file.
pub enum BinaryFormat {
    /// Portable Executable (Windows `.exe`, `.dll`, `.sys`, object files, ...).
    Pe,
    /// Executable and Linkable Format (Linux/Unix executables, shared objects, ...).
    Elf,
}

/// Byte offsets of each field within the COFF File Header, relative to the
/// start of that header (i.e. relative to the NT header offset found at
/// file offset `0x3C`, *not* relative to the start of the file).
///
/// The COFF File Header is 20 bytes (`0x14`) long in total. See:
/// <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image>
pub enum CoffFileHeaderOffset {
    /// `u16` — the target CPU architecture. See [`PeMachineType`].
    Machine = 0x0,
    /// `u16` — number of section table entries following the headers.
    NumberOfSections = 0x2,
    /// `u32` — low 32 bits of the number of seconds since the Unix epoch,
    /// i.e. when the file was created.
    TimeDateStamp = 0x4,
    /// `u32` — file offset of the COFF symbol table, or zero if none is
    /// present. Deprecated in modern PE images.
    PointerToSymbolTable = 0x8,
    /// `u32` — number of entries in the symbol table above.
    NumberOfSymbols = 0xC,
    /// `u16` — size in bytes of the Optional Header, which immediately
    /// follows this header. Required for executable images.
    SizeOfOptionalHeader = 0x10,
    /// `u16` — bit flags describing attributes of the file (e.g. whether
    /// it is executable, a DLL, stripped of debug info, etc).
    Characteristics = 0x12,
}

/// Machine types recognized in the COFF File Header's `Machine` field
/// (see [`CoffFileHeaderOffset::Machine`]). Backed by `u16` to match the
/// field's on-disk width. See:
/// <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image>
#[repr(u16)]
pub enum PeMachineType {
    /// The content of this field is assumed to be applicable to any machine type.
    Unknown = 0x0,
    Alpha = 0x184,
    Alpha64 = 0x284,
    Am33 = 0x1D3,
    /// x64.
    Amd64 = 0x8664,
    /// ARM little endian.
    Arm = 0x1C0,
    /// ARM64 little endian.
    Arm64 = 0xAA64,
    /// ARM64EC ("emulation compatible").
    Arm64Ec = 0xA641,
    /// ARM64X (mixed ARM64/ARM64EC binary).
    Arm64X = 0xA64E,
    /// ARM Thumb-2 little endian.
    ArmNt = 0x1C4,
    /// EFI byte code.
    Ebc = 0xEBC,
    /// Intel 386 or later, and compatible processors.
    I386 = 0x14C,
    /// Intel Itanium.
    Ia64 = 0x200,
    LoongArch32 = 0x6232,
    LoongArch64 = 0x6264,
    M32R = 0x9041,
    Mips16 = 0x266,
    MipsFpu = 0x366,
    MipsFpu16 = 0x466,
    PowerPc = 0x1F0,
    /// PowerPC with floating point support.
    PowerPcFp = 0x1F1,
    /// MIPS little endian.
    R4000 = 0x166,
    RiscV32 = 0x5032,
    RiscV64 = 0x5064,
    RiscV128 = 0x5128,
    Sh3 = 0x1A2,
    Sh3Dsp = 0x1A3,
    Sh4 = 0x1A6,
    Sh5 = 0x1A8,
    /// ARM or Thumb ("interworking").
    Thumb = 0x1C2,
    /// MIPS little-endian WCE v2.
    WceMipsV2 = 0x169,
}

impl TryFrom<u16> for PeMachineType {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self> {
        Ok(match value {
            0x0 => PeMachineType::Unknown,
            0x184 => PeMachineType::Alpha,
            0x284 => PeMachineType::Alpha64,
            0x1D3 => PeMachineType::Am33,
            0x8664 => PeMachineType::Amd64,
            0x1C0 => PeMachineType::Arm,
            0xAA64 => PeMachineType::Arm64,
            0xA641 => PeMachineType::Arm64Ec,
            0xA64E => PeMachineType::Arm64X,
            0x1C4 => PeMachineType::ArmNt,
            0xEBC => PeMachineType::Ebc,
            0x14C => PeMachineType::I386,
            0x200 => PeMachineType::Ia64,
            0x6232 => PeMachineType::LoongArch32,
            0x6264 => PeMachineType::LoongArch64,
            0x9041 => PeMachineType::M32R,
            0x266 => PeMachineType::Mips16,
            0x366 => PeMachineType::MipsFpu,
            0x466 => PeMachineType::MipsFpu16,
            0x1F0 => PeMachineType::PowerPc,
            0x1F1 => PeMachineType::PowerPcFp,
            0x166 => PeMachineType::R4000,
            0x5032 => PeMachineType::RiscV32,
            0x5064 => PeMachineType::RiscV64,
            0x5128 => PeMachineType::RiscV128,
            0x1A2 => PeMachineType::Sh3,
            0x1A3 => PeMachineType::Sh3Dsp,
            0x1A6 => PeMachineType::Sh4,
            0x1A8 => PeMachineType::Sh5,
            0x1C2 => PeMachineType::Thumb,
            0x169 => PeMachineType::WceMipsV2,
            other => return Err(anyhow::anyhow!("unknown PE machine type: {other:#x}")),
        })
    }
}

/// Value of the Optional Header's `Magic` field, identifying which of the
/// two Optional Header layouts is in use. See:
/// <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only>
#[repr(u16)]
pub enum OptionalHeaderMagic {
    /// 32-bit image. `BaseOfData` is present and `ImageBase`/stack/heap
    /// size fields are 4 bytes wide.
    Pe32 = 0x10B,
    /// 64-bit image ("PE32+"). `BaseOfData` is omitted and `ImageBase`/
    /// stack/heap size fields are 8 bytes wide.
    Pe32Plus = 0x20B,
    /// ROM image. Not used by the Windows loader; included for completeness.
    Rom = 0x107,
}

/// Index (0-based) of each well-known entry in the Optional Header's Data
/// Directory array. Each entry is an 8-byte `IMAGE_DATA_DIRECTORY`
/// (`VirtualAddress: u32`, `Size: u32`); the byte offset of entry `N` from
/// the start of the array is `N * 8`. See:
/// <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only>
pub enum DataDirectoryOffset {
    ExportTable = 0,
    ImportTable = 1,
    ResourceTable = 2,
    ExceptionTable = 3,
    /// Attribute certificate table — unlike the others, this one is a file
    /// offset rather than an RVA.
    CertificateTable = 4,
    BaseRelocationTable = 5,
    Debug = 6,
    /// Reserved, must be zero.
    Architecture = 7,
    GlobalPtr = 8,
    TlsTable = 9,
    LoadConfigTable = 10,
    BoundImport = 11,
    /// Import Address Table.
    Iat = 12,
    DelayImportDescriptor = 13,
    /// CLR runtime header (.NET images).
    ClrRuntimeHeader = 14,
    /// Reserved, must be zero.
    Reserved = 15,
}

/// A single parsed Data Directory entry.
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// Parsed Optional Header fields, common to both PE32 and PE32+.
pub struct OptionalHeader {
    pub magic: OptionalHeaderMagic,
    pub address_of_entry_point: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    /// Indexed by [`DataDirectoryOffset`].
    pub data_directories: Vec<DataDirectory>,
}

/// Byte offsets of each field within a single Section Table entry
/// (`IMAGE_SECTION_HEADER`), relative to the start of that entry. Each
/// entry is 40 bytes (`0x28`) long; the section table itself immediately
/// follows the Optional Header, and has `NumberOfSections`
/// ([`CoffFileHeaderOffset::NumberOfSections`]) entries. See:
/// <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers>
pub enum SectionHeaderOffset {
    /// `[u8; 8]` — UTF-8, null-padded, *not* necessarily null-terminated
    /// (a full 8-character name has no terminator).
    Name = 0x0,
    /// `u32` — total size of the section when loaded into memory. May be
    /// larger than `SizeOfRawData` (the rest is zero-filled).
    VirtualSize = 0x8,
    /// `u32` — RVA of the section when loaded into memory.
    VirtualAddress = 0xC,
    /// `u32` — size of the section's raw data on disk, rounded up to
    /// `FileAlignment`.
    SizeOfRawData = 0x10,
    /// `u32` — file offset of the section's raw data.
    PointerToRawData = 0x14,
    /// `u32` — file offset of relocation entries. Zero for images.
    PointerToRelocations = 0x18,
    /// `u32` — file offset of line-number entries. Deprecated.
    PointerToLinenumbers = 0x1C,
    /// `u16` — number of relocation entries. Zero for images.
    NumberOfRelocations = 0x20,
    /// `u16` — number of line-number entries. Deprecated.
    NumberOfLinenumbers = 0x22,
    /// `u32` — bit flags, e.g. whether the section is executable,
    /// readable, writable, or contains code/initialized/uninitialized data.
    Characteristics = 0x24,
}

/// A single parsed Section Table entry.
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

/// Parsed information about a PE binary.
pub struct PEInformation {
    Machine: PeMachineType,
    // paranoid even tho this might waste just a bit of memory
    Format: BinaryFormat,
    OptionalHeader: OptionalHeader,
    Sections: Vec<SectionHeader>,
}

/// Parsed information about an ELF binary.
// TODO: Add this
pub struct ElfInformation {}

/// Result of inspecting a file's contents: at most one of these will be
/// populated, depending on which format was detected.
pub struct BinaryInfo {
    PEInf: Option<PEInformation>,
    ElfInf: Option<ElfInformation>,
}

/// Grab and return specific bytes from offset and give those requested bytes, Wrapped in a Result<>
fn get_n_bytes_from_bytes<'a>(bytes: &'a [u8], offset: usize, n: usize) -> Result<&'a [u8]> {
    bytes.get(offset..offset + n).ok_or_else(|| {
        anyhow::anyhow!(
            "expected {n} bytes at offset {offset:#x}, but only {} bytes are available",
            bytes.len()
        )
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let b = get_n_bytes_from_bytes(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let b = get_n_bytes_from_bytes(bytes, offset, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let b = get_n_bytes_from_bytes(bytes, offset, 8)?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// Returns 1 if it is succeeded in finding the bytes that a PE has, otherwise not.
fn check_for_pe(bytes: &[u8]) -> Result<u8> {
    let returned_bytes = get_n_bytes_from_bytes(bytes, 0x00, 2)?;

    if (returned_bytes[0] == 0x4D && returned_bytes[1] == 0x5A) {
        return Ok(1);
    } else {
        return Ok(0);
    }
}

fn get_pe_information(bytes: &[u8]) -> Result<Option<PEInformation>> {
    // assuming this is a valid pe header file
    if check_for_pe(bytes)? != 1 {
        return Err(anyhow::anyhow!("not a PE file"));
    }

    // `e_lfanew`, in the DOS header: file offset of the `"PE\0\0"` signature.
    const E_LFANEW_OFFSET: usize = 0x3C;
    let signature_offset = read_u32(bytes, E_LFANEW_OFFSET)? as usize;

    let signature = get_n_bytes_from_bytes(bytes, signature_offset, 4)?;
    if signature != &b"PE\0\0"[..] {
        return Err(anyhow::anyhow!(
            "expected PE signature at offset {signature_offset:#x}"
        ));
    }

    // The COFF File Header immediately follows the 4-byte signature.
    let coff_header_offset = signature_offset + 4;
    const COFF_HEADER_SIZE: usize = 0x14;

    let machine = PeMachineType::try_from(read_u16(
        bytes,
        coff_header_offset + CoffFileHeaderOffset::Machine as usize,
    )?)?;
    let number_of_sections = read_u16(
        bytes,
        coff_header_offset + CoffFileHeaderOffset::NumberOfSections as usize,
    )?;
    let size_of_optional_header = read_u16(
        bytes,
        coff_header_offset + CoffFileHeaderOffset::SizeOfOptionalHeader as usize,
    )?;

    let optional_header_offset = coff_header_offset + COFF_HEADER_SIZE;
    let optional_header = get_optional_header(bytes, optional_header_offset)?;

    let section_table_offset = optional_header_offset + size_of_optional_header as usize;
    const SECTION_HEADER_SIZE: usize = 0x28;
    let mut sections = Vec::with_capacity(number_of_sections as usize);
    for i in 0..number_of_sections as usize {
        sections.push(get_section_header(
            bytes,
            section_table_offset + i * SECTION_HEADER_SIZE,
        )?);
    }

    Ok(Some(PEInformation {
        Machine: machine,
        Format: BinaryFormat::Pe,
        OptionalHeader: optional_header,
        Sections: sections,
    }))
}

/// Parses the Optional Header (`IMAGE_OPTIONAL_HEADER32`/`64`) starting at
/// `offset`. PE32 and PE32+ differ in the width of `ImageBase` and in
/// whether `BaseOfData` is present, but those differences cancel out: both
/// layouts resume at the same offset (`0x20`) for `SectionAlignment` onward.
fn get_optional_header(bytes: &[u8], offset: usize) -> Result<OptionalHeader> {
    let magic = match read_u16(bytes, offset)? {
        0x10B => OptionalHeaderMagic::Pe32,
        0x20B => OptionalHeaderMagic::Pe32Plus,
        0x107 => OptionalHeaderMagic::Rom,
        other => return Err(anyhow::anyhow!("unknown optional header magic: {other:#x}")),
    };

    let address_of_entry_point = read_u32(bytes, offset + 0x10)?;

    let (image_base, fixed_fields_offset, address_field_size) = match &magic {
        OptionalHeaderMagic::Pe32Plus => (read_u64(bytes, offset + 0x18)?, offset + 0x20, 8usize),
        _ => (
            read_u32(bytes, offset + 0x1C)? as u64,
            offset + 0x20,
            4usize,
        ),
    };

    let section_alignment = read_u32(bytes, fixed_fields_offset)?;
    let file_alignment = read_u32(bytes, fixed_fields_offset + 0x4)?;
    let size_of_image = read_u32(bytes, fixed_fields_offset + 0x18)?;
    let size_of_headers = read_u32(bytes, fixed_fields_offset + 0x1C)?;
    let subsystem = read_u16(bytes, fixed_fields_offset + 0x24)?;
    let dll_characteristics = read_u16(bytes, fixed_fields_offset + 0x26)?;

    // Stack/heap reserve+commit sizes (4 fields, `u32` for PE32 / `u64` for
    // PE32+) are followed by `LoaderFlags: u32` then `NumberOfRvaAndSizes: u32`.
    let number_of_rva_and_sizes_offset = fixed_fields_offset + 0x28 + address_field_size * 4 + 0x4;
    let number_of_rva_and_sizes = read_u32(bytes, number_of_rva_and_sizes_offset)?;

    let data_directory_offset = number_of_rva_and_sizes_offset + 4;
    let mut data_directories = Vec::with_capacity(number_of_rva_and_sizes as usize);
    for i in 0..number_of_rva_and_sizes as usize {
        let entry_offset = data_directory_offset + i * 8;
        data_directories.push(DataDirectory {
            virtual_address: read_u32(bytes, entry_offset)?,
            size: read_u32(bytes, entry_offset + 4)?,
        });
    }

    Ok(OptionalHeader {
        magic,
        address_of_entry_point,
        image_base,
        section_alignment,
        file_alignment,
        size_of_image,
        size_of_headers,
        subsystem,
        dll_characteristics,
        data_directories,
    })
}

/// Parses a single Section Table entry (`IMAGE_SECTION_HEADER`) at `offset`.
fn get_section_header(bytes: &[u8], offset: usize) -> Result<SectionHeader> {
    let mut name = [0u8; 8];
    name.copy_from_slice(get_n_bytes_from_bytes(
        bytes,
        offset + SectionHeaderOffset::Name as usize,
        8,
    )?);

    Ok(SectionHeader {
        name,
        virtual_size: read_u32(bytes, offset + SectionHeaderOffset::VirtualSize as usize)?,
        virtual_address: read_u32(bytes, offset + SectionHeaderOffset::VirtualAddress as usize)?,
        size_of_raw_data: read_u32(bytes, offset + SectionHeaderOffset::SizeOfRawData as usize)?,
        pointer_to_raw_data: read_u32(
            bytes,
            offset + SectionHeaderOffset::PointerToRawData as usize,
        )?,
        characteristics: read_u32(
            bytes,
            offset + SectionHeaderOffset::Characteristics as usize,
        )?,
    })
}

/// Detects the binary format of `bytes` and parses out its header
/// information.
pub fn get_file_type(bytes: &Vec<u8>) -> Result<BinaryInfo> {
    // we try to find each of the PE and elf
    get_pe_information(bytes)?;
    Err(anyhow::anyhow!(
        "Unix or other binary formats are not supported"
    ))
}

/// Builders for the synthetic binaries the tests feed to the parsers, shared
/// with the tests in `crate::file::load`.
#[cfg(test)]
pub(crate) mod test_support {
    /// One Section Table entry to synthesize.
    #[derive(Clone)]
    pub(crate) struct SectionSpec {
        pub name: [u8; 8],
        pub virtual_size: u32,
        pub virtual_address: u32,
        pub size_of_raw_data: u32,
        pub pointer_to_raw_data: u32,
        pub characteristics: u32,
    }

    impl SectionSpec {
        /// A plausible code section called `name`, null-padded to 8 bytes.
        /// Names of exactly 8 bytes are stored without a terminator, as the
        /// format allows.
        pub(crate) fn named(name: &[u8]) -> Self {
            let mut padded = [0u8; 8];
            padded[..name.len()].copy_from_slice(name);
            Self {
                name: padded,
                virtual_size: 0x1000,
                virtual_address: 0x1000,
                size_of_raw_data: 0x200,
                pointer_to_raw_data: 0x400,
                characteristics: 0x6000_0020,
            }
        }
    }

    /// Assembles a minimal but well-formed PE image in memory: DOS header,
    /// `"PE\0\0"` signature, COFF File Header, Optional Header and Section
    /// Table. Every field a test might want to corrupt is overridable, so
    /// malformed inputs are built by tweaking one field of [`Default`].
    pub(crate) struct PeBuilder {
        /// Bytes at offset `0x00`; `b"MZ"` for a real PE.
        pub dos_magic: [u8; 2],
        /// What the DOS header claims at `0x3C`. Defaults to `nt_offset`,
        /// i.e. the truth.
        pub e_lfanew: Option<u32>,
        /// Where the `"PE\0\0"` signature is actually written.
        pub nt_offset: usize,
        /// Bytes written at `nt_offset`; `b"PE\0\0"` for a real PE.
        pub pe_signature: [u8; 4],
        pub machine: u16,
        /// What the COFF header claims. Defaults to `sections.len()`.
        pub number_of_sections: Option<u16>,
        /// What the COFF header claims. Defaults to the real size.
        pub size_of_optional_header: Option<u16>,
        /// `0x10B` (PE32), `0x20B` (PE32+) or `0x107` (ROM).
        pub optional_magic: u16,
        pub address_of_entry_point: u32,
        /// Truncated to 32 bits when `optional_magic` is not PE32+.
        pub image_base: u64,
        pub section_alignment: u32,
        pub file_alignment: u32,
        pub size_of_image: u32,
        pub size_of_headers: u32,
        pub subsystem: u16,
        pub dll_characteristics: u16,
        /// `(VirtualAddress, Size)` pairs actually written out.
        pub data_directories: Vec<(u32, u32)>,
        /// What `NumberOfRvaAndSizes` claims. Defaults to the real count.
        pub number_of_rva_and_sizes: Option<u32>,
        pub sections: Vec<SectionSpec>,
    }

    impl Default for PeBuilder {
        /// A valid x64 PE32+ image with 16 empty data directories and a
        /// single `.text` section.
        fn default() -> Self {
            Self {
                dos_magic: *b"MZ",
                e_lfanew: None,
                nt_offset: 0x80,
                pe_signature: *b"PE\0\0",
                machine: 0x8664,
                number_of_sections: None,
                size_of_optional_header: None,
                optional_magic: 0x20B,
                address_of_entry_point: 0x1000,
                image_base: 0x0001_4000_0000,
                section_alignment: 0x1000,
                file_alignment: 0x200,
                size_of_image: 0x4000,
                size_of_headers: 0x400,
                subsystem: 3,
                dll_characteristics: 0x8160,
                data_directories: vec![(0, 0); 16],
                number_of_rva_and_sizes: None,
                sections: vec![SectionSpec::named(b".text")],
            }
        }
    }

    impl PeBuilder {
        /// Byte offset of the Data Directory array within the Optional
        /// Header, which is where the fixed part of the header ends.
        fn data_directory_offset(&self) -> usize {
            if self.optional_magic == 0x20B {
                0x70
            } else {
                0x60
            }
        }

        pub(crate) fn build(&self) -> Vec<u8> {
            // The DOS header needs room for `e_lfanew` at 0x3C.
            assert!(self.nt_offset >= 0x40, "nt_offset must clear the DOS header");

            let dir_offset = self.data_directory_offset();
            let optional_header_len = dir_offset + self.data_directories.len() * 8;
            let declared_optional_header_len = self
                .size_of_optional_header
                .unwrap_or(optional_header_len as u16);

            // DOS header plus stub padding.
            let mut out = vec![0u8; self.nt_offset];
            out[0x00..0x02].copy_from_slice(&self.dos_magic);
            let e_lfanew = self.e_lfanew.unwrap_or(self.nt_offset as u32);
            out[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

            out.extend_from_slice(&self.pe_signature);

            // COFF File Header.
            let mut coff = [0u8; 0x14];
            coff[0x00..0x02].copy_from_slice(&self.machine.to_le_bytes());
            let number_of_sections = self
                .number_of_sections
                .unwrap_or(self.sections.len() as u16);
            coff[0x02..0x04].copy_from_slice(&number_of_sections.to_le_bytes());
            coff[0x10..0x12].copy_from_slice(&declared_optional_header_len.to_le_bytes());
            out.extend_from_slice(&coff);

            // Optional Header.
            let mut opt = vec![0u8; optional_header_len];
            opt[0x00..0x02].copy_from_slice(&self.optional_magic.to_le_bytes());
            opt[0x10..0x14].copy_from_slice(&self.address_of_entry_point.to_le_bytes());
            if self.optional_magic == 0x20B {
                opt[0x18..0x20].copy_from_slice(&self.image_base.to_le_bytes());
            } else {
                // PE32 keeps `BaseOfData` at 0x18 and a 4-byte `ImageBase`.
                opt[0x1C..0x20].copy_from_slice(&(self.image_base as u32).to_le_bytes());
            }
            opt[0x20..0x24].copy_from_slice(&self.section_alignment.to_le_bytes());
            opt[0x24..0x28].copy_from_slice(&self.file_alignment.to_le_bytes());
            opt[0x38..0x3C].copy_from_slice(&self.size_of_image.to_le_bytes());
            opt[0x3C..0x40].copy_from_slice(&self.size_of_headers.to_le_bytes());
            opt[0x44..0x46].copy_from_slice(&self.subsystem.to_le_bytes());
            opt[0x46..0x48].copy_from_slice(&self.dll_characteristics.to_le_bytes());
            let declared_dirs = self
                .number_of_rva_and_sizes
                .unwrap_or(self.data_directories.len() as u32);
            opt[dir_offset - 4..dir_offset].copy_from_slice(&declared_dirs.to_le_bytes());
            for (i, (virtual_address, size)) in self.data_directories.iter().enumerate() {
                let at = dir_offset + i * 8;
                opt[at..at + 4].copy_from_slice(&virtual_address.to_le_bytes());
                opt[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
            }
            out.extend_from_slice(&opt);

            // Section Table.
            for section in &self.sections {
                let mut entry = [0u8; 0x28];
                entry[0x00..0x08].copy_from_slice(&section.name);
                entry[0x08..0x0C].copy_from_slice(&section.virtual_size.to_le_bytes());
                entry[0x0C..0x10].copy_from_slice(&section.virtual_address.to_le_bytes());
                entry[0x10..0x14].copy_from_slice(&section.size_of_raw_data.to_le_bytes());
                entry[0x14..0x18].copy_from_slice(&section.pointer_to_raw_data.to_le_bytes());
                entry[0x24..0x28].copy_from_slice(&section.characteristics.to_le_bytes());
                out.extend_from_slice(&entry);
            }

            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{PeBuilder, SectionSpec};
    use super::*;

    /// Offset of the Optional Header in a [`PeBuilder`] image left at its
    /// default `nt_offset`: signature (4 bytes) plus COFF header (0x14).
    const DEFAULT_OPTIONAL_HEADER_OFFSET: usize = 0x80 + 4 + 0x14;

    fn err_string<T>(result: Result<T>) -> String {
        format!("{:#}", result.err().expect("expected an error"))
    }

    // --- get_n_bytes_from_bytes -------------------------------------------

    #[test]
    fn get_n_bytes_returns_the_requested_window() {
        let bytes = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        assert_eq!(
            get_n_bytes_from_bytes(&bytes, 1, 3).unwrap(),
            &[0xBB, 0xCC, 0xDD]
        );
    }

    #[test]
    fn get_n_bytes_allows_a_window_ending_exactly_at_the_end() {
        let bytes = [1u8, 2, 3];
        assert_eq!(get_n_bytes_from_bytes(&bytes, 1, 2).unwrap(), &[2, 3]);
        // A zero-length read at the very end is still in range.
        assert_eq!(get_n_bytes_from_bytes(&bytes, 3, 0).unwrap(), &[] as &[u8]);
    }

    #[test]
    fn get_n_bytes_rejects_a_window_running_past_the_end() {
        let bytes = [1u8, 2, 3];
        let message = err_string(get_n_bytes_from_bytes(&bytes, 2, 2));
        assert!(
            message.contains("expected 2 bytes at offset 0x2") && message.contains("3 bytes"),
            "unexpected message: {message}"
        );
    }

    #[test]
    fn get_n_bytes_rejects_an_offset_past_the_end() {
        assert!(get_n_bytes_from_bytes(&[1u8, 2, 3], 9, 1).is_err());
        assert!(get_n_bytes_from_bytes(&[], 0, 1).is_err());
    }

    // --- read_u16 / read_u32 / read_u64 -----------------------------------

    #[test]
    fn integer_reads_are_little_endian() {
        let bytes = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        assert_eq!(read_u16(&bytes, 0).unwrap(), 0x2211);
        assert_eq!(read_u16(&bytes, 1).unwrap(), 0x3322);
        assert_eq!(read_u32(&bytes, 0).unwrap(), 0x4433_2211);
        assert_eq!(read_u64(&bytes, 0).unwrap(), 0x8877_6655_4433_2211);
        assert_eq!(read_u64(&bytes, 1).unwrap(), 0x9988_7766_5544_3322);
    }

    #[test]
    fn integer_reads_reject_truncated_input() {
        let bytes = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        assert!(read_u16(&bytes, 6).is_err());
        assert!(read_u32(&bytes, 4).is_err());
        assert!(read_u64(&bytes, 0).is_err());
    }

    // --- PeMachineType ----------------------------------------------------

    /// Every machine type the enum declares, so the `TryFrom` arms and the
    /// discriminants cannot drift apart.
    const ALL_MACHINE_TYPES: &[u16] = &[
        0x0, 0x184, 0x284, 0x1D3, 0x8664, 0x1C0, 0xAA64, 0xA641, 0xA64E, 0x1C4, 0xEBC, 0x14C,
        0x200, 0x6232, 0x6264, 0x9041, 0x266, 0x366, 0x466, 0x1F0, 0x1F1, 0x166, 0x5032, 0x5064,
        0x5128, 0x1A2, 0x1A3, 0x1A6, 0x1A8, 0x1C2, 0x169,
    ];

    #[test]
    fn every_known_machine_type_round_trips() {
        for &value in ALL_MACHINE_TYPES {
            let parsed = PeMachineType::try_from(value)
                .unwrap_or_else(|e| panic!("{value:#x} should be known: {e}"));
            assert_eq!(parsed as u16, value, "{value:#x} maps to the wrong variant");
        }
    }

    #[test]
    fn well_known_machine_types_map_to_the_expected_variants() {
        assert!(matches!(
            PeMachineType::try_from(0x8664).unwrap(),
            PeMachineType::Amd64
        ));
        assert!(matches!(
            PeMachineType::try_from(0x14C).unwrap(),
            PeMachineType::I386
        ));
        assert!(matches!(
            PeMachineType::try_from(0xAA64).unwrap(),
            PeMachineType::Arm64
        ));
        // Zero is a documented value ("any machine type"), not an error.
        assert!(matches!(
            PeMachineType::try_from(0x0).unwrap(),
            PeMachineType::Unknown
        ));
    }

    #[test]
    fn unrecognized_machine_type_is_an_error() {
        let message = err_string(PeMachineType::try_from(0xDEAD));
        assert!(
            message.contains("unknown PE machine type") && message.contains("0xdead"),
            "unexpected message: {message}"
        );
    }

    // --- check_for_pe -----------------------------------------------------

    #[test]
    fn check_for_pe_recognizes_the_mz_magic() {
        assert_eq!(check_for_pe(b"MZ").unwrap(), 1);
        assert_eq!(check_for_pe(&[0x4D, 0x5A, 0x90, 0x00]).unwrap(), 1);
    }

    #[test]
    fn check_for_pe_rejects_other_magics() {
        assert_eq!(check_for_pe(b"\x7fELF").unwrap(), 0);
        assert_eq!(check_for_pe(b"ZM").unwrap(), 0, "the magic is order-sensitive");
        assert_eq!(check_for_pe(&[0x00, 0x00]).unwrap(), 0);
    }

    #[test]
    fn check_for_pe_errors_when_there_is_no_magic_to_read() {
        assert!(check_for_pe(&[]).is_err());
        assert!(check_for_pe(&[0x4D]).is_err());
    }

    // --- get_optional_header ----------------------------------------------

    #[test]
    fn parses_a_pe32_plus_optional_header() {
        let bytes = PeBuilder {
            data_directories: vec![(0x1000, 0x50), (0x2000, 0x60)],
            ..Default::default()
        }
        .build();

        let header = get_optional_header(&bytes, DEFAULT_OPTIONAL_HEADER_OFFSET).unwrap();

        assert!(matches!(header.magic, OptionalHeaderMagic::Pe32Plus));
        assert_eq!(header.address_of_entry_point, 0x1000);
        assert_eq!(header.image_base, 0x0001_4000_0000);
        assert_eq!(header.section_alignment, 0x1000);
        assert_eq!(header.file_alignment, 0x200);
        assert_eq!(header.size_of_image, 0x4000);
        assert_eq!(header.size_of_headers, 0x400);
        assert_eq!(header.subsystem, 3);
        assert_eq!(header.dll_characteristics, 0x8160);
        assert_eq!(header.data_directories.len(), 2);
        assert_eq!(header.data_directories[0].virtual_address, 0x1000);
        assert_eq!(header.data_directories[0].size, 0x50);
        assert_eq!(header.data_directories[1].virtual_address, 0x2000);
        assert_eq!(header.data_directories[1].size, 0x60);
    }

    /// PE32 puts `ImageBase` at a different offset and uses 4-byte stack and
    /// heap sizes, which shifts the data directories; the parser has to track
    /// both differences.
    #[test]
    fn parses_a_pe32_optional_header() {
        let bytes = PeBuilder {
            optional_magic: 0x10B,
            machine: 0x14C,
            image_base: 0x0040_0000,
            data_directories: vec![(0xABCD, 0x10)],
            ..Default::default()
        }
        .build();

        let header = get_optional_header(&bytes, DEFAULT_OPTIONAL_HEADER_OFFSET).unwrap();

        assert!(matches!(header.magic, OptionalHeaderMagic::Pe32));
        assert_eq!(header.image_base, 0x0040_0000);
        assert_eq!(header.address_of_entry_point, 0x1000);
        assert_eq!(header.section_alignment, 0x1000);
        assert_eq!(header.size_of_headers, 0x400);
        assert_eq!(header.subsystem, 3);
        assert_eq!(header.data_directories.len(), 1);
        assert_eq!(header.data_directories[0].virtual_address, 0xABCD);
        assert_eq!(header.data_directories[0].size, 0x10);
    }

    #[test]
    fn accepts_the_rom_optional_header_magic() {
        let bytes = PeBuilder {
            optional_magic: 0x107,
            ..Default::default()
        }
        .build();

        let header = get_optional_header(&bytes, DEFAULT_OPTIONAL_HEADER_OFFSET).unwrap();
        assert!(matches!(header.magic, OptionalHeaderMagic::Rom));
    }

    #[test]
    fn an_optional_header_with_no_data_directories_parses_to_an_empty_vec() {
        let bytes = PeBuilder {
            data_directories: vec![],
            ..Default::default()
        }
        .build();

        let header = get_optional_header(&bytes, DEFAULT_OPTIONAL_HEADER_OFFSET).unwrap();
        assert!(header.data_directories.is_empty());
    }

    #[test]
    fn unknown_optional_header_magic_is_an_error() {
        let bytes = PeBuilder {
            optional_magic: 0x1234,
            ..Default::default()
        }
        .build();

        let message = err_string(get_optional_header(&bytes, DEFAULT_OPTIONAL_HEADER_OFFSET));
        assert!(
            message.contains("unknown optional header magic") && message.contains("0x1234"),
            "unexpected message: {message}"
        );
    }

    #[test]
    fn a_truncated_optional_header_is_an_error() {
        let mut bytes = PeBuilder::default().build();
        // Keep the magic but cut the header off partway through.
        bytes.truncate(DEFAULT_OPTIONAL_HEADER_OFFSET + 0x30);
        assert!(get_optional_header(&bytes, DEFAULT_OPTIONAL_HEADER_OFFSET).is_err());
    }

    /// `NumberOfRvaAndSizes` comes from the file, so a corrupt count must not
    /// be trusted past the end of the buffer.
    #[test]
    fn a_data_directory_count_larger_than_the_file_is_an_error() {
        let bytes = PeBuilder {
            data_directories: vec![(0, 0); 2],
            number_of_rva_and_sizes: Some(4096),
            ..Default::default()
        }
        .build();

        assert!(get_optional_header(&bytes, DEFAULT_OPTIONAL_HEADER_OFFSET).is_err());
    }

    // --- get_section_header -----------------------------------------------

    #[test]
    fn parses_a_section_header() {
        let section = SectionSpec {
            virtual_size: 0x1234,
            virtual_address: 0x2000,
            size_of_raw_data: 0x400,
            pointer_to_raw_data: 0x600,
            characteristics: 0xC000_0040,
            ..SectionSpec::named(b".rdata")
        };
        let bytes = PeBuilder {
            sections: vec![section],
            ..Default::default()
        }
        .build();
        // The section table follows the whole header block.
        let offset = bytes.len() - 0x28;

        let parsed = get_section_header(&bytes, offset).unwrap();

        assert_eq!(&parsed.name, b".rdata\0\0");
        assert_eq!(parsed.virtual_size, 0x1234);
        assert_eq!(parsed.virtual_address, 0x2000);
        assert_eq!(parsed.size_of_raw_data, 0x400);
        assert_eq!(parsed.pointer_to_raw_data, 0x600);
        assert_eq!(parsed.characteristics, 0xC000_0040);
    }

    /// An 8-character name fills the field with no null terminator.
    #[test]
    fn parses_a_section_name_that_fills_the_whole_field() {
        let bytes = PeBuilder {
            sections: vec![SectionSpec::named(b".reloc12")],
            ..Default::default()
        }
        .build();

        let parsed = get_section_header(&bytes, bytes.len() - 0x28).unwrap();
        assert_eq!(&parsed.name, b".reloc12");
    }

    #[test]
    fn a_truncated_section_header_is_an_error() {
        let mut bytes = PeBuilder::default().build();
        let offset = bytes.len() - 0x28;
        // Drop the trailing `Characteristics` field.
        bytes.truncate(bytes.len() - 4);
        assert!(get_section_header(&bytes, offset).is_err());
    }

    // --- get_pe_information -----------------------------------------------

    #[test]
    fn parses_a_whole_pe_image() {
        let bytes = PeBuilder {
            sections: vec![
                SectionSpec::named(b".text"),
                SectionSpec {
                    virtual_address: 0x3000,
                    ..SectionSpec::named(b".data")
                },
            ],
            ..Default::default()
        }
        .build();

        let info = get_pe_information(&bytes).unwrap().expect("a PE was parsed");

        assert!(matches!(info.Machine, PeMachineType::Amd64));
        assert!(matches!(info.Format, BinaryFormat::Pe));
        assert!(matches!(
            info.OptionalHeader.magic,
            OptionalHeaderMagic::Pe32Plus
        ));
        assert_eq!(info.OptionalHeader.data_directories.len(), 16);
        assert_eq!(info.Sections.len(), 2);
        assert_eq!(&info.Sections[0].name, b".text\0\0\0");
        assert_eq!(&info.Sections[1].name, b".data\0\0\0");
        assert_eq!(info.Sections[1].virtual_address, 0x3000);
    }

    #[test]
    fn a_pe_with_no_sections_parses_to_an_empty_section_list() {
        let bytes = PeBuilder {
            sections: vec![],
            ..Default::default()
        }
        .build();

        let info = get_pe_information(&bytes).unwrap().unwrap();
        assert!(info.Sections.is_empty());
    }

    #[test]
    fn a_file_without_the_mz_magic_is_not_a_pe() {
        let bytes = PeBuilder {
            dos_magic: *b"ZZ",
            ..Default::default()
        }
        .build();

        assert_eq!(err_string(get_pe_information(&bytes)), "not a PE file");
    }

    #[test]
    fn an_empty_file_is_not_a_pe() {
        assert!(get_pe_information(&[]).is_err());
    }

    #[test]
    fn a_dos_header_without_an_nt_header_is_an_error() {
        // "MZ" and nothing else: `e_lfanew` itself cannot be read.
        assert!(get_pe_information(b"MZ").is_err());
    }

    #[test]
    fn a_missing_pe_signature_is_an_error() {
        let bytes = PeBuilder {
            pe_signature: *b"NE\0\0",
            ..Default::default()
        }
        .build();

        let message = err_string(get_pe_information(&bytes));
        assert!(
            message.contains("expected PE signature at offset 0x80"),
            "unexpected message: {message}"
        );
    }

    #[test]
    fn an_e_lfanew_pointing_past_the_end_of_the_file_is_an_error() {
        let bytes = PeBuilder {
            e_lfanew: Some(0x00FF_FFFF),
            ..Default::default()
        }
        .build();

        assert!(get_pe_information(&bytes).is_err());
    }

    #[test]
    fn an_unknown_machine_type_fails_the_whole_parse() {
        let bytes = PeBuilder {
            machine: 0x1234,
            ..Default::default()
        }
        .build();

        let message = err_string(get_pe_information(&bytes));
        assert!(
            message.contains("unknown PE machine type"),
            "unexpected message: {message}"
        );
    }

    /// `NumberOfSections` is attacker-controlled data; claiming more sections
    /// than the file holds must fail rather than read out of bounds.
    #[test]
    fn a_section_count_larger_than_the_file_is_an_error() {
        let bytes = PeBuilder {
            number_of_sections: Some(500),
            ..Default::default()
        }
        .build();

        assert!(get_pe_information(&bytes).is_err());
    }

    /// The section table is located via the declared `SizeOfOptionalHeader`,
    /// so an inflated value must not send the parser off the end.
    #[test]
    fn an_oversized_optional_header_size_is_an_error() {
        let bytes = PeBuilder {
            size_of_optional_header: Some(0x7FFF),
            ..Default::default()
        }
        .build();

        assert!(get_pe_information(&bytes).is_err());
    }

    // --- get_file_type ----------------------------------------------------

    #[test]
    fn get_file_type_rejects_non_pe_input() {
        let bytes = b"\x7fELF\x02\x01\x01\x00".to_vec();
        assert_eq!(err_string(get_file_type(&bytes)), "not a PE file");
    }

    /// Current behavior: even a PE that parses cleanly comes back as an
    /// error, because `get_file_type` discards the parsed information and
    /// falls through to the "unsupported format" arm.
    // TODO: when `get_file_type` returns the parsed `BinaryInfo`, replace this
    // with an assertion that `PEInf` is populated and `ElfInf` is `None`.
    #[test]
    fn get_file_type_currently_discards_a_successfully_parsed_pe() {
        let bytes = PeBuilder::default().build();

        assert!(get_pe_information(&bytes).is_ok(), "the fixture is a valid PE");
        assert_eq!(
            err_string(get_file_type(&bytes)),
            "Unix or other binary formats are not supported"
        );
    }
}
