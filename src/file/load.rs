use anyhow::Result;

use std::fs::read;
use std::path::PathBuf;

use crate::checker::filetype::{BinaryInfo, get_file_type};

pub struct Sh0k0h3xFile {
    pub file_buffer: Vec<u8>,
    pub file_type: BinaryInfo,
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::checker::filetype::test_support::PeBuilder;

    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A file under the system temp directory that deletes itself when the
    /// test ends, so the tests do not touch the repository or each other.
    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn with_contents(name: &str, contents: &[u8]) -> Self {
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);

            let mut path = std::env::temp_dir();
            path.push(format!(
                "sh0k0hex-test-{}-{unique}-{name}",
                std::process::id()
            ));
            fs::write(&path, contents).expect("failed to write the test fixture");

            Self { path }
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn err_string(result: Result<Sh0k0h3xFile>) -> String {
        format!("{:#}", result.err().expect("expected an error"))
    }

    #[test]
    fn a_missing_file_reports_the_io_error() {
        let mut path = std::env::temp_dir();
        path.push(format!("sh0k0hex-does-not-exist-{}", std::process::id()));
        assert!(!path.exists(), "the fixture path must not exist");

        let error = load_file_raw_bytes(&path).err().expect("expected an error");
        let io_error = error
            .downcast_ref::<std::io::Error>()
            .expect("the io::Error should be preserved");
        assert_eq!(io_error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn a_directory_is_not_loadable() {
        assert!(load_file_raw_bytes(&std::env::temp_dir()).is_err());
    }

    #[test]
    fn an_empty_file_is_rejected_by_the_type_checker() {
        let file = TempFile::with_contents("empty.bin", &[]);
        assert!(load_file_raw_bytes(&file.path).is_err());
    }

    /// Detection errors come straight from `get_file_type`, not wrapped.
    #[test]
    fn a_non_pe_file_is_rejected_with_the_detection_error() {
        let file = TempFile::with_contents("hello.txt", b"hello, this is not a binary\n");
        assert_eq!(err_string(load_file_raw_bytes(&file.path)), "not a PE file");
    }

    #[test]
    fn a_truncated_pe_is_rejected() {
        let mut bytes = PeBuilder::default().build();
        bytes.truncate(0x90);
        let file = TempFile::with_contents("truncated.exe", &bytes);

        assert!(load_file_raw_bytes(&file.path).is_err());
    }

    /// Current behavior: a valid PE still fails to load, because
    /// `get_file_type` never returns `Ok`. Loading is therefore unreachable
    /// for every input today.
    // TODO: delete this once `get_file_type` returns the parsed information;
    // `loads_a_valid_pe` below then covers the success path.
    #[test]
    fn a_valid_pe_currently_fails_to_load() {
        let file = TempFile::with_contents("valid.exe", &PeBuilder::default().build());

        assert_eq!(
            err_string(load_file_raw_bytes(&file.path)),
            "Unix or other binary formats are not supported"
        );
    }

    /// The intended success path: the whole file is buffered, and the name
    /// and size are taken from the path and the buffer. Ignored until
    /// `get_file_type` stops returning an error for valid PE files.
    #[test]
    #[ignore = "blocked on get_file_type returning Ok for PE files"]
    fn loads_a_valid_pe() {
        let bytes = PeBuilder::default().build();
        let file = TempFile::with_contents("valid.exe", &bytes);

        let loaded = load_file_raw_bytes(&file.path).expect("a valid PE should load");

        assert_eq!(loaded.file_buffer, bytes);
        assert_eq!(loaded.file_size, bytes.len());
        assert_eq!(
            loaded.file_name,
            file.path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        );
    }
}
