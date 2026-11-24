# -*- encoding: utf-8 -*-
# stub: chef-telemetry 1.1.1 ruby lib

Gem::Specification.new do |s|
  s.name = "chef-telemetry".freeze
  s.version = "1.1.1".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Chef Software, Inc.".freeze]
  s.date = "2021-07-26"
  s.email = "info@chef.io".freeze
  s.homepage = "https://github.com/chef/chef-telemetry".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.5".freeze)
  s.rubygems_version = "3.1.4".freeze
  s.summary = "Send user actions to the Chef telemetry system. See Chef RFC-051 for further information".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<concurrent-ruby>.freeze, ["~> 1.0".freeze])
  s.add_runtime_dependency(%q<chef-config>.freeze, [">= 0".freeze])
end
