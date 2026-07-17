mod api;
mod credentials;
mod model;
mod ui;
mod zip;

use wasm_bindgen::JsValue;

pub fn start() -> Result<(), JsValue> {
    ui::start()
}
