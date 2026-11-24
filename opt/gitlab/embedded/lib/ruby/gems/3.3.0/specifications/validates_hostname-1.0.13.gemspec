# -*- encoding: utf-8 -*-
# stub: validates_hostname 1.0.13 ruby lib

Gem::Specification.new do |s|
  s.name = "validates_hostname".freeze
  s.version = "1.0.13".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Kim N\u00F8gaard".freeze]
  s.date = "2022-10-14"
  s.description = "Extension to ActiveRecord::Base for validating hostnames".freeze
  s.email = "jasen@jasen.dk".freeze
  s.extra_rdoc_files = ["README.rdoc".freeze, "CHANGELOG.rdoc".freeze, "MIT-LICENSE".freeze]
  s.files = ["CHANGELOG.rdoc".freeze, "MIT-LICENSE".freeze, "README.rdoc".freeze]
  s.homepage = "https://github.com/KimNorgaard/validates_hostname".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "3.3.23".freeze
  s.summary = "Checks for valid hostnames".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<activerecord>.freeze, [">= 3.0".freeze])
  s.add_runtime_dependency(%q<activesupport>.freeze, [">= 3.0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.0".freeze])
  s.add_development_dependency(%q<rspec-rails>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rails>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<sqlite3>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<pry-byebug>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rspec-collection_matchers>.freeze, [">= 0".freeze])
end
