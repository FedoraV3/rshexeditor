use anyhow::Result;

mod checker;
mod core;
mod file;
mod imgui;

fn main() -> Result<()> {
    core::run()?;
    Ok(())
}
