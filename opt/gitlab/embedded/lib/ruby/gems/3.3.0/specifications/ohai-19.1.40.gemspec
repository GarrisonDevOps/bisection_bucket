# -*- encoding: utf-8 -*-
# stub: ohai 19.1.40 ruby lib

Gem::Specification.new do |s|
  s.name = "ohai".freeze
  s.version = "19.1.40".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Adam Jacob".freeze]
  s.date = "2026-06-24"
  s.description = "Ohai profiles your system and emits JSON".freeze
  s.email = "adam@chef.io".freeze
  s.executables = ["ohai".freeze]
  s.files = ["bin/ohai".freeze]
  s.homepage = "https://github.com/chef/ohai/".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.1".freeze)
  s.rubygems_version = "3.3.27".freeze
  s.summary = "Ohai profiles your system and emits JSON".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<base64>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<chef-config>.freeze, [">= 14.12".freeze, "< 20".freeze])
  s.add_runtime_dependency(%q<chef-utils>.freeze, [">= 16.0".freeze, "< 20".freeze])
  s.add_runtime_dependency(%q<ffi>.freeze, [">= 1.15.5".freeze])
  s.add_runtime_dependency(%q<ffi-yajl>.freeze, [">= 2.2".freeze, "< 3.0".freeze])
  s.add_runtime_dependency(%q<ipaddress>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<mixlib-cli>.freeze, [">= 1.7.0".freeze])
  s.add_runtime_dependency(%q<mixlib-config>.freeze, [">= 2.0".freeze, "< 4.0".freeze])
  s.add_runtime_dependency(%q<mixlib-log>.freeze, [">= 2.0.1".freeze, "< 4.0".freeze])
  s.add_runtime_dependency(%q<mixlib-shellout>.freeze, [">= 3.3.6".freeze, "< 3.5.0".freeze])
  s.add_runtime_dependency(%q<plist>.freeze, ["~> 3.1".freeze])
  s.add_runtime_dependency(%q<train-core>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<wmi-lite>.freeze, ["~> 1.0".freeze])
end
