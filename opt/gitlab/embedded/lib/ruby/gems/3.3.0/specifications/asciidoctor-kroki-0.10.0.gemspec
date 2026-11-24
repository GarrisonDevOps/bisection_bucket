# -*- encoding: utf-8 -*-
# stub: asciidoctor-kroki 0.10.0 ruby lib

Gem::Specification.new do |s|
  s.name = "asciidoctor-kroki".freeze
  s.version = "0.10.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://github.com/ggrossetie/asciidoctor-kroki/issues", "rubygems_mfa_required" => "true", "source_code_uri" => "https://github.com/ggrossetie/asciidoctor-kroki" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Guillaume Grossetie".freeze]
  s.date = "2024-03-21"
  s.description = "An extension for Asciidoctor to convert diagrams to images using https://kroki.io".freeze
  s.email = ["ggrossetie@yuzutech.fr".freeze]
  s.homepage = "https://github.com/ggrossetie/asciidoctor-kroki".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "3.1.6".freeze
  s.summary = "Asciidoctor extension to convert diagrams to images using Kroki".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<asciidoctor>.freeze, ["~> 2.0".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 13.0.6".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.10.0".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, ["~> 1.30".freeze])
end
