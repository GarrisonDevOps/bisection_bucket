# -*- encoding: utf-8 -*-
# stub: oj-introspect 0.9.0 ruby lib
# stub: ext/oj-introspect/extconf.rb

Gem::Specification.new do |s|
  s.name = "oj-introspect".freeze
  s.version = "0.9.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Mehmet Emin INAC".freeze]
  s.bindir = "exe".freeze
  s.date = "2026-03-13"
  s.description = "Embeds start and end byte offsets of JSON objects into generated Ruby hashes.".freeze
  s.email = ["mehmetemininac@gmail.com".freeze]
  s.extensions = ["ext/oj-introspect/extconf.rb".freeze]
  s.files = ["ext/oj-introspect/extconf.rb".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/ruby/gems/oj-introspect".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.3.0".freeze)
  s.rubygems_version = "3.5.22".freeze
  s.summary = "Oj introspect parser.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<oj>.freeze, [">= 3.16.16".freeze])
end
