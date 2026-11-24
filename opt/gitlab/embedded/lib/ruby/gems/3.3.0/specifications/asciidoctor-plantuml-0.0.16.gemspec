# -*- encoding: utf-8 -*-
# stub: asciidoctor-plantuml 0.0.16 ruby lib

Gem::Specification.new do |s|
  s.name = "asciidoctor-plantuml".freeze
  s.version = "0.0.16".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "rubygems_mfa_required" => "true" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Horacio Sanson".freeze]
  s.date = "2022-04-30"
  s.description = "Asciidoctor PlantUML extension".freeze
  s.email = ["hsanson@gmail.com".freeze]
  s.homepage = "https://github.com/hsanson/asciidoctor-plantuml".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.6".freeze)
  s.rubygems_version = "3.1.2".freeze
  s.summary = "Asciidoctor support for PlantUML diagrams.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<bundler>.freeze, ["~> 2.2".freeze])
  s.add_development_dependency(%q<nokogiri>.freeze, ["~> 1.13.4".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 13.0".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, ["~> 1.28".freeze])
  s.add_development_dependency(%q<test-unit>.freeze, ["~> 3.5".freeze])
  s.add_runtime_dependency(%q<asciidoctor>.freeze, [">= 2.0.17".freeze, "< 3.0.0".freeze])
end
