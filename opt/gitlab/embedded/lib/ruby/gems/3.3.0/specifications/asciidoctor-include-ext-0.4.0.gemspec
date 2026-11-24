# -*- encoding: utf-8 -*-
# stub: asciidoctor-include-ext 0.4.0 ruby lib

Gem::Specification.new do |s|
  s.name = "asciidoctor-include-ext".freeze
  s.version = "0.4.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Jakub Jirutka".freeze]
  s.date = "2022-03-29"
  s.description = "This is a reimplementation of the Asciidoctor's built-in (pre)processor for the\ninclude::[] directive in extensible and more clean way. It provides the same\nfeatures, but you can easily adjust it or extend for your needs. For example,\nyou can change how it loads included files or add another ways how to select\nportions of the document to include.\n".freeze
  s.email = "jakub@jirutka.cz".freeze
  s.homepage = "https://github.com/jirutka/asciidoctor-include-ext".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.3".freeze)
  s.rubygems_version = "3.3.7".freeze
  s.summary = "Asciidoctor's standard include::[] processor reimplemented as an extension".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<asciidoctor>.freeze, [">= 1.5.6".freeze, "< 3.0.0".freeze])
  s.add_development_dependency(%q<kramdown>.freeze, ["~> 2.0".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 13.0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.7".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, ["~> 0.51.0".freeze])
  s.add_development_dependency(%q<simplecov>.freeze, ["~> 0.15".freeze])
  s.add_development_dependency(%q<yard>.freeze, ["~> 0.9".freeze])
end
