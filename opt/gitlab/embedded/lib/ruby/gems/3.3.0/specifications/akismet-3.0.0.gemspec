# -*- encoding: utf-8 -*-
# stub: akismet 3.0.0 ruby lib

Gem::Specification.new do |s|
  s.name = "akismet".freeze
  s.version = "3.0.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Jonah Burke".freeze]
  s.date = "2019-08-03"
  s.email = ["jonah@jonahb.com".freeze]
  s.homepage = "http://github.com/jonahb/akismet".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.4".freeze)
  s.rubygems_version = "3.0.3".freeze
  s.summary = "A Ruby client for the Akismet API".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<bundler>.freeze, [">= 1.7".freeze])
  s.add_development_dependency(%q<minitest>.freeze, ["~> 5.11".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 12.0".freeze])
  s.add_development_dependency(%q<yard>.freeze, ["~> 0.9.20".freeze])
end
