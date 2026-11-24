# -*- encoding: utf-8 -*-
# stub: em-resolv-replace 1.1.3 ruby lib

Gem::Specification.new do |s|
  s.name = "em-resolv-replace".freeze
  s.version = "1.1.3".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Mike Perham".freeze]
  s.date = "2012-07-17"
  s.email = "mperham@gmail.com".freeze
  s.extra_rdoc_files = ["LICENSE".freeze, "History.rdoc".freeze, "README.rdoc".freeze]
  s.files = ["History.rdoc".freeze, "LICENSE".freeze, "README.rdoc".freeze]
  s.homepage = "http://github.com/mperham/em-resolv-replace".freeze
  s.rdoc_options = ["--charset=UTF-8".freeze]
  s.rubygems_version = "1.8.15".freeze
  s.summary = "EventMachine-aware DNS lookup for Ruby".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 3

  s.add_development_dependency(%q<shoulda>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<mocha>.freeze, [">= 0".freeze])
end
