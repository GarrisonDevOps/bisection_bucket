use comrak::{escape_commonmark_inline, escape_commonmark_link_destination};
use magnus::{function, prelude::*, Error, RHash, RString, Ruby};
use serde_magnus::deserialize;

mod formatter;
mod glfm;
use glfm::{render, RenderOptions};

pub fn render_to_html_rs(ruby: &Ruby, text: RString, options: RHash) -> Result<String, Error> {
    let render_options: RenderOptions = deserialize(ruby, options)?;

    // SAFETY: `RString::as_str` returns a reference directly to Ruby memory.
    // We do not hold onto or save the `&str`, or otherwise permit Ruby to GC or
    // modify it while in `glfm::render`.
    // https://docs.rs/magnus/latest/magnus/r_string/struct.RString.html#method.as_str
    Ok(render(unsafe { text.as_str()? }, &render_options))
}

pub fn escape_commonmark_inline_rs(text: RString) -> Result<String, Error> {
    // SAFETY: `RString::as_str` returns a reference directly to Ruby memory.
    // We do not hold onto or save the `&str`, or otherwise permit Ruby to GC or
    // modify it while in `glfm::escape_commonmark_inline`.
    // https://docs.rs/magnus/latest/magnus/r_string/struct.RString.html#method.as_str
    Ok(escape_commonmark_inline(unsafe { text.as_str()? }))
}

pub fn escape_commonmark_link_destination_rs(text: RString) -> Result<String, Error> {
    // SAFETY: `RString::as_str` returns a reference directly to Ruby memory.
    // We do not hold onto or save the `&str`, or otherwise permit Ruby to GC or
    // modify it while in `glfm::escape_commonmark_link_destination`.
    // https://docs.rs/magnus/latest/magnus/r_string/struct.RString.html#method.as_str
    Ok(escape_commonmark_link_destination(unsafe {
        text.as_str()?
    }))
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.define_module("GLFMMarkdown")?;

    module.define_singleton_method("render_to_html_rs", function!(render_to_html_rs, 2))?;
    module.define_singleton_method(
        "escape_commonmark_inline_rs",
        function!(escape_commonmark_inline_rs, 1),
    )?;
    module.define_singleton_method(
        "escape_commonmark_link_destination_rs",
        function!(escape_commonmark_link_destination_rs, 1),
    )?;

    Ok(())
}
