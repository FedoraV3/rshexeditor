use anyhow::Result;
use imgui::Context;
use imgui_glow_renderer::{
    AutoRenderer,
    glow::{self},
};
use imgui_sdl2_support::SdlPlatform;
use sdl2::video::{GLContext, GLProfile};
use sdl2::{
    EventPump,
    sys::{SDL_Event, SDL_EventType::*},
};
use std::os::raw::{c_int, c_void};

/* render_frame(
    &window,
    &mut imgui,
    &mut platform,
    &mut renderer,
    &mut event_pump,
).unwrap(); */

#[allow(dead_code)]
pub struct RenderCtx {
    pub window: sdl2::video::Window,
    pub gl_context: GLContext,
    pub imgui_ctx: imgui::Context,
    pub platform: SdlPlatform,
    pub renderer: AutoRenderer,
    pub event_pump: EventPump,
}

// impl RenderCtx {
//     pub fn new(
//         window: sdl2::video::Window,
//         gl_context: GLContext,
//         imgui_ctx: imgui::Context,
//         platform: SdlPlatform,
//         renderer: AutoRenderer,
//         event_pump: EventPump,
//     ) -> RenderCtx {
//         RenderCtx {
//             window: window,
//             gl_context: gl_context,
//             imgui_ctx: imgui_ctx,
//             platform: platform,
//             renderer: renderer,
//             event_pump: event_pump,
//         }
//     }
// }

/// sdl2-compat (the SDL2-over-SDL3 shim shipped on some Linux distros, e.g. Arch)
/// forwards some SDL3-only event type codes (such as the per-window pixel-size-
/// changed event, fired right at window creation for a high-DPI window) without
/// translating them back into a legacy SDL2 event. The `sdl2` crate transmutes the
/// raw type code straight into its `SDL_EventType` enum, which only knows the
/// codes SDL2 itself ever defined, and panics on anything else. Drop those before
/// they reach the event queue instead of letting the whole app crash on them.
unsafe extern "C" fn drop_unknown_events(_userdata: *mut c_void, event: *mut SDL_Event) -> c_int {
    const KNOWN_EVENT_TYPES: &[u32] = &[
        SDL_FIRSTEVENT as u32,
        SDL_QUIT as u32,
        SDL_APP_TERMINATING as u32,
        SDL_APP_LOWMEMORY as u32,
        SDL_APP_WILLENTERBACKGROUND as u32,
        SDL_APP_DIDENTERBACKGROUND as u32,
        SDL_APP_WILLENTERFOREGROUND as u32,
        SDL_APP_DIDENTERFOREGROUND as u32,
        SDL_LOCALECHANGED as u32,
        SDL_DISPLAYEVENT as u32,
        SDL_WINDOWEVENT as u32,
        SDL_SYSWMEVENT as u32,
        SDL_KEYDOWN as u32,
        SDL_KEYUP as u32,
        SDL_TEXTEDITING as u32,
        SDL_TEXTINPUT as u32,
        SDL_KEYMAPCHANGED as u32,
        SDL_TEXTEDITING_EXT as u32,
        SDL_MOUSEMOTION as u32,
        SDL_MOUSEBUTTONDOWN as u32,
        SDL_MOUSEBUTTONUP as u32,
        SDL_MOUSEWHEEL as u32,
        SDL_JOYAXISMOTION as u32,
        SDL_JOYBALLMOTION as u32,
        SDL_JOYHATMOTION as u32,
        SDL_JOYBUTTONDOWN as u32,
        SDL_JOYBUTTONUP as u32,
        SDL_JOYDEVICEADDED as u32,
        SDL_JOYDEVICEREMOVED as u32,
        SDL_JOYBATTERYUPDATED as u32,
        SDL_CONTROLLERAXISMOTION as u32,
        SDL_CONTROLLERBUTTONDOWN as u32,
        SDL_CONTROLLERBUTTONUP as u32,
        SDL_CONTROLLERDEVICEADDED as u32,
        SDL_CONTROLLERDEVICEREMOVED as u32,
        SDL_CONTROLLERDEVICEREMAPPED as u32,
        SDL_CONTROLLERTOUCHPADDOWN as u32,
        SDL_CONTROLLERTOUCHPADMOTION as u32,
        SDL_CONTROLLERTOUCHPADUP as u32,
        SDL_CONTROLLERSENSORUPDATE as u32,
        SDL_FINGERDOWN as u32,
        SDL_FINGERUP as u32,
        SDL_FINGERMOTION as u32,
        SDL_DOLLARGESTURE as u32,
        SDL_DOLLARRECORD as u32,
        SDL_MULTIGESTURE as u32,
        SDL_CLIPBOARDUPDATE as u32,
        SDL_DROPFILE as u32,
        SDL_DROPTEXT as u32,
        SDL_DROPBEGIN as u32,
        SDL_DROPCOMPLETE as u32,
        SDL_AUDIODEVICEADDED as u32,
        SDL_AUDIODEVICEREMOVED as u32,
        SDL_SENSORUPDATE as u32,
        SDL_RENDER_TARGETS_RESET as u32,
        SDL_RENDER_DEVICE_RESET as u32,
        SDL_POLLSENTINEL as u32,
    ];

    let event_type = unsafe { (*event).type_ };
    let is_known = KNOWN_EVENT_TYPES.contains(&event_type)
        || (SDL_USEREVENT as u32..=SDL_LASTEVENT as u32).contains(&event_type);

    if is_known { 1 } else { 0 }
}

#[allow(unused_mut)]
pub fn imgui_init() -> Result<RenderCtx> {
    let sdl = sdl2::init().unwrap();

    /* filter out event types this crate's SDL2 bindings don't know about
     * before they reach the queue (see drop_unknown_events) */
    unsafe {
        sdl2::sys::SDL_SetEventFilter(Some(drop_unknown_events), std::ptr::null_mut());
    }

    let video_subsystem = sdl.video().unwrap();

    /* hint SDL to initialize an OpenGL 3.3 core profile context */
    let gl_attr = video_subsystem.gl_attr();

    gl_attr.set_context_version(3, 3);
    gl_attr.set_context_profile(GLProfile::Core);

    /* create a new window, be sure to call opengl method on the builder when using glow! */
    let window = video_subsystem
        .window("Sh0k0H3x", 1280, 720)
        .allow_highdpi()
        .opengl()
        .position_centered()
        .resizable()
        .build()
        .unwrap();

    /* create a new OpenGL context and make it current */
    let gl_context = window.gl_create_context().unwrap();
    window.gl_make_current(&gl_context).unwrap();

    /* enable vsync to cap framerate */
    window.subsystem().gl_set_swap_interval(1).unwrap();

    /* create new glow and imgui contexts */
    let gl;
    unsafe {
        gl = glow::Context::from_loader_function(|s| window.subsystem().gl_get_proc_address(s) as _)
    }

    /* create context */
    let mut imgui = Context::create();

    /* setup platform and renderer, and fonts to imgui */
    imgui
        .fonts()
        .add_font(&[imgui::FontSource::DefaultFontData { config: None }]);

    /* create platform and renderer */
    let mut platform = SdlPlatform::new(&mut imgui);
    let mut renderer = AutoRenderer::new(gl, &mut imgui).unwrap();

    /* start main loop */
    let mut event_pump = sdl.event_pump().unwrap();

    /* pass control to the main program loop as the setup is done */
    Ok({
        RenderCtx { window, gl_context, imgui_ctx: imgui, platform, renderer, event_pump }
    })
}
