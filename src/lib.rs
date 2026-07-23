#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
mod server;
#[cfg(target_arch = "wasm64")]
mod web;

#[cfg(target_arch = "wasm32")]
compile_error!("Session Bridge browser frontend requires wasm64-unknown-unknown");

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
pub use server::build_app;

#[cfg(target_arch = "wasm64")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm64")]
#[wasm_bindgen(start)]
pub fn start() -> Result<(), JsValue> {
    web::start()
}
