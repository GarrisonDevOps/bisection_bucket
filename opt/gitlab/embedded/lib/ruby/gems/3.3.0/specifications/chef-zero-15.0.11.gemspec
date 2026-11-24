# -*- encoding: utf-8 -*-
# stub: chef-zero 15.0.11 ruby lib

Gem::Specification.new do |s|
  s.name = "chef-zero".freeze
  s.version = "15.0.11".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Chef Software, Inc.".freeze, "Cinc Project".freeze]
  s.date = "2021-10-27"
  s.description = "Self-contained, easy-setup, fast-start in-memory Chef server for testing and solo setup purposes".freeze
  s.email = ["oss@chef.io".freeze, "maintainers@cinc.sh".freeze]
  s.executables = ["cinc-zero".freeze]
  s.files = ["bin/cinc-zero".freeze]
  s.homepage = "https://gitlab.com/cinc-project/chef-zero".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.6".freeze)
  s.rubygems_version = "3.2.15".freeze
  s.summary = "Self-contained, easy-setup, fast-start in-memory Chef server for testing and solo setup purposes".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<mixlib-log>.freeze, [">= 2.0".freeze, "< 4.0".freeze])
  s.add_runtime_dependency(%q<hashie>.freeze, [">= 2.0".freeze, "< 5.0".freeze])
  s.add_runtime_dependency(%q<uuidtools>.freeze, ["~> 2.1".freeze])
  s.add_runtime_dependency(%q<ffi-yajl>.freeze, ["~> 2.2".freeze])
  s.add_runtime_dependency(%q<rack>.freeze, ["~> 2.0".freeze, ">= 2.0.6".freeze])
  s.add_runtime_dependency(%q<webrick>.freeze, [">= 0".freeze])
end
