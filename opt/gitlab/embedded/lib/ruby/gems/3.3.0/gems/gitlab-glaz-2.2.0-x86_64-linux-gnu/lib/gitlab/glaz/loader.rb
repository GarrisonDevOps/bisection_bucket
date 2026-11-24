# frozen_string_literal: true

# Native-gem installs ship a per-Ruby-ABI .so under lib/gitlab/glaz/<X.Y>/glaz.so.
# Source-gem installs (or local `rake compile` output) put it at lib/gitlab/glaz/glaz.{so,bundle}.
# Try the version-specific path first, fall back to the flat layout.
def load_rust_extension
  ruby_version = /(\d+\.\d+)/.match(RUBY_VERSION)
  require "gitlab/glaz/#{ruby_version}/glaz"
rescue LoadError
  require "gitlab/glaz/glaz"
end
