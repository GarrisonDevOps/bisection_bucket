# -*- encoding: utf-8 -*-
# stub: chef-licensing 0.7.5 ruby lib

Gem::Specification.new do |s|
  s.name = "chef-licensing".freeze
  s.version = "0.7.5".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "homepage_uri" => "https://github.com/chef/chef-licensing", "source_code_uri" => "https://github.com/chef/chef-licensing" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Inspec Team".freeze]
  s.bindir = "exe".freeze
  s.date = "2023-10-10"
  s.description = "Ruby library to support CLI tools that use Progress Chef license storage, generation, and entitlement.".freeze
  s.email = ["inspec@progress.com".freeze]
  s.homepage = "https://github.com/chef/chef-licensing".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.3.0".freeze)
  s.rubygems_version = "3.1.4".freeze
  s.summary = "Chef License storage, generation, and entitlement".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<chef-config>.freeze, [">= 15".freeze])
  s.add_runtime_dependency(%q<tty-prompt>.freeze, ["~> 0.23".freeze])
  s.add_runtime_dependency(%q<faraday>.freeze, [">= 1".freeze, "< 3".freeze])
  s.add_runtime_dependency(%q<faraday-http-cache>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<activesupport>.freeze, ["~> 7.0".freeze, "< 7.1".freeze])
  s.add_runtime_dependency(%q<tty-spinner>.freeze, ["~> 0.9.3".freeze])
end
