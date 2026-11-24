# -*- encoding: utf-8 -*-
# stub: gitlab-glaz 2.2.0 x86_64-linux-gnu lib

Gem::Specification.new do |s|
  s.name = "gitlab-glaz".freeze
  s.version = "2.2.0".freeze
  s.platform = "x86_64-linux-gnu".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 3.3.22".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["group::authorization".freeze]
  s.date = "2026-11-11"
  s.description = "Wraps the Rust-backed GitLab Authorization Service (GLAZ) exposed via magnus FFI".freeze
  s.email = ["engineering@gitlab.com".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/ruby/gems/gitlab-glaz".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new([">= 3.1".freeze, "< 4.1.dev".freeze])
  s.rubygems_version = "3.5.23".freeze
  s.summary = "Ruby client for the GLAZ authorization engine".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<google-protobuf>.freeze, ["~> 4.35".freeze])
  s.add_runtime_dependency(%q<rb_sys>.freeze, ["~> 0.9.128".freeze])
  s.add_development_dependency(%q<gitlab-styles>.freeze, ["~> 14.1".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.12".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, ["~> 1.81".freeze])
end
