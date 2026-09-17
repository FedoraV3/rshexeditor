use std::process::exit;

use anyhow::Result;
use imgui_glow_renderer::{glow, glow::HasContext};
use sdl2::{event::Event};

use crate::imgui::init::RenderCtx;

pub fn render_frame(ctx: &mut RenderCtx) -> Result<()> {
    for event in ctx.event_pump.poll_iter() {
        /* pass all events to imgui platfrom */
        ctx.platform.handle_event(&mut ctx.imgui_ctx, &event);
        if let Event::Quit { .. } = event {
            exit(0);
        }
    }

    /* render */
    ctx.platform.prepare_frame(&mut ctx.imgui_ctx, &mut ctx.window, &mut ctx.event_pump);

    {
        let ui = ctx.imgui_ctx.frame();
        let display_size = ui.io().display_size;

        ui.window("Sh0k0H3x")
            .position([0.0, 0.0], imgui::Condition::Always)
            .size(display_size, imgui::Condition::Always)
            .title_bar(false)
            .resizable(false)
            .movable(false)
            .scroll_bar(false)
            .collapsible(false)
            .bring_to_front_on_focus(false)
            .build(|| {
                ui.text("initializing..");
            });
    }
    let draw_data = ctx.imgui_ctx.render();

    unsafe { ctx.renderer.gl_context().clear(glow::COLOR_BUFFER_BIT) };
    ctx.renderer.render(draw_data).map_err(anyhow::Error::msg)?;
    ctx.window.gl_swap_window();

    Ok(())
}
