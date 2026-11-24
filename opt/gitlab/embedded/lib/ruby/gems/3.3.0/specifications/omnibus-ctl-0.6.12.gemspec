# -*- encoding: utf-8 -*-
# stub: omnibus-ctl 0.6.12 ruby lib

Gem::Specification.new do |s|
  s.name = "omnibus-ctl".freeze
  s.version = "0.6.12".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Chef Software, Inc.".freeze]
  s.date = "1980-01-02"
  s.description = "Provides command line control for omnibus pakcages, rarely used as a gem".freeze
  s.email = ["legal@chef.io".freeze]
  s.executables = ["omnibus-ctl".freeze]
  s.files = ["bin/omnibus-ctl".freeze]
  s.homepage = "http://github.com/chef/omnibus-ctl".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.6".freeze)
  s.rubygems_version = "3.7.2".freeze
  s.summary = "Provides command line control for omnibus packages".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<chef-utils>.freeze, [">= 16.5.54".freeze])
  s.add_development_dependency(%q<chefstyle>.freeze, ["= 2.2.0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.2".freeze])
  s.add_development_dependency(%q<rspec_junit_formatter>.freeze, [">= 0".freeze])
end
