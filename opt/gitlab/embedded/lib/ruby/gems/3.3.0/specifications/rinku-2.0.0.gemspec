# -*- encoding: utf-8 -*-
# stub: rinku 2.0.0 ruby lib
# stub: ext/rinku/extconf.rb

Gem::Specification.new do |s|
  s.name = "rinku".freeze
  s.version = "2.0.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Vicent Marti".freeze]
  s.date = "2016-05-19"
  s.description = "    A fast and very smart autolinking library that\n    acts as a drop-in replacement for Rails `auto_link`\n".freeze
  s.email = "vicent@github.com".freeze
  s.extensions = ["ext/rinku/extconf.rb".freeze]
  s.extra_rdoc_files = ["COPYING".freeze]
  s.files = ["COPYING".freeze, "ext/rinku/extconf.rb".freeze]
  s.homepage = "https://github.com/vmg/rinku".freeze
  s.rubygems_version = "2.2.5".freeze
  s.summary = "Mostly autolinking".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<rake>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake-compiler>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<minitest>.freeze, [">= 0".freeze])
end
