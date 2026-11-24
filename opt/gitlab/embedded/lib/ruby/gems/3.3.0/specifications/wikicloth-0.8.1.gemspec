# -*- encoding: utf-8 -*-
# stub: wikicloth 0.8.1 ruby lib

Gem::Specification.new do |s|
  s.name = "wikicloth".freeze
  s.version = "0.8.1".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["David Ricciardi".freeze]
  s.date = "2014-01-07"
  s.description = "mediawiki parser".freeze
  s.email = "nricciar@gmail.com".freeze
  s.extra_rdoc_files = ["README".freeze, "MIT-LICENSE".freeze]
  s.files = ["MIT-LICENSE".freeze, "README".freeze]
  s.homepage = "http://github.com/nricciar/wikicloth".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "1.8.25".freeze
  s.summary = "An implementation of the mediawiki markup in ruby".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 3

  s.add_runtime_dependency(%q<builder>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<expression_parser>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<rinku>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<test-unit>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<activesupport>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<i18n>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rdoc>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<simplecov>.freeze, [">= 0".freeze])
end
