# frozen_string_literal: true

def load_rust_extension
  ruby_version = /(\d+\.\d+)/.match(RUBY_VERSION)
  require "gitlab_glfm_markdown/#{ruby_version}/gitlab_glfm_markdown"
rescue LoadError
  require 'gitlab_glfm_markdown/gitlab_glfm_markdown'
end
