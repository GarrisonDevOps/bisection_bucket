# -*- encoding: utf-8 -*-
# stub: duo_api 1.5.1 ruby lib

Gem::Specification.new do |s|
  s.name = "duo_api".freeze
  s.version = "1.5.1".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Duo Security".freeze]
  s.date = "2025-10-14"
  s.description = "A Ruby implementation of the Duo API.".freeze
  s.email = "support@duo.com".freeze
  s.homepage = "https://github.com/duosecurity/duo_api_ruby".freeze
  s.licenses = ["BSD-3-Clause".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.5".freeze)
  s.rubygems_version = "3.4.19".freeze
  s.summary = "Duo API Ruby".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<base64>.freeze, [">= 0.2.0".freeze])
  s.add_development_dependency(%q<mocha>.freeze, ["~> 2.7.1".freeze])
  s.add_development_dependency(%q<ostruct>.freeze, ["~> 0.6.1".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 13.2.1".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, ["~> 1.73.1".freeze])
  s.add_development_dependency(%q<test-unit>.freeze, ["~> 3.6.7".freeze])
end
