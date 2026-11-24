# frozen_string_literal: true

require 'mkmf'
require 'rb_sys/mkmf'

create_rust_makefile('gitlab_glfm_markdown/gitlab_glfm_markdown') do |r|
  r.auto_install_rust_toolchain = false
  # Ensure all Rust dependencies are pinned when building
  r.extra_cargo_args = ["--locked"]
end
