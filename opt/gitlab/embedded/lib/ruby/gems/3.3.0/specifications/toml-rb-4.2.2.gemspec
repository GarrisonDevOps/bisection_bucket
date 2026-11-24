# -*- encoding: utf-8 -*-
# stub: toml-rb 4.2.2 ruby lib

Gem::Specification.new do |s|
  s.name = "toml-rb".freeze
  s.version = "4.2.2".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Emiliano Mancuso".freeze, "Lucas Tolchinsky".freeze]
  s.date = "2026-09-27"
  s.description = "A Toml parser using Citrus parsing library. ".freeze
  s.email = ["emiliano.mancuso@gmail.com".freeze, "lucas.tolchinsky@gmail.com".freeze]
  s.homepage = "https://github.com/emancu/toml-rb".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.5".freeze)
  s.rubygems_version = "3.6.2".freeze
  s.summary = "Toml parser in ruby, for ruby.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<citrus>.freeze, ["~> 3.0".freeze, "> 3.0".freeze])
  s.add_runtime_dependency(%q<racc>.freeze, ["~> 1.7".freeze])
  s.add_development_dependency(%q<minitest>.freeze, ["~> 5.7".freeze])
  s.add_development_dependency(%q<standard>.freeze, ["~> 1.4".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0".freeze])
end
