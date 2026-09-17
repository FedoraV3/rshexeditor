use anyhow::Result;
use crate::imgui::{gui::render_frame, init::imgui_init};

pub fn run() -> Result<()> {
    let mut render_ctx = imgui_init()?;
    
    // main program loop
    loop {
        render_frame(&mut render_ctx)?;
    }
}