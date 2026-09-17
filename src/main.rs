use anyhow::Result;

mod core;
mod imgui;
mod file;

fn main() -> Result<()> {
    core::run()?;
    Ok(())
}
