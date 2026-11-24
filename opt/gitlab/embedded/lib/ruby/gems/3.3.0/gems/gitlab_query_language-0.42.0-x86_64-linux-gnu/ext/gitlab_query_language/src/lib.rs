use magnus::{function, prelude::*, Error, Ruby};

fn compile_rs(query: String, string_context: String) -> Result<String, Error> {
    Ok(glql::compile(query.as_str(), string_context.as_str()))
}

fn transform_rs(data: String, string_context: String) -> Result<String, Error> {
    Ok(glql::transform(data.as_str(), string_context.as_str()))
}

fn schema_rs() -> Result<String, Error> {
    Ok(glql::glql_schema())
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.define_module("Glql")?;

    module.define_singleton_method("compile_rs", function!(compile_rs, 2))?;
    module.define_singleton_method("transform_rs", function!(transform_rs, 2))?;
    module.define_singleton_method("schema_rs", function!(schema_rs, 0))?;

    Ok(())
}
