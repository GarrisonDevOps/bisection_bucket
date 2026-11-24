# frozen_string_literal: true

require "mkmf"
require "rb_sys/mkmf"

create_rust_makefile("gitlab/glaz/glaz") do |r|
  r.auto_install_rust_toolchain = true
end
