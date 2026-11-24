# -*- encoding: utf-8 -*-
# stub: jsonb_accessor 1.4.2 ruby lib

Gem::Specification.new do |s|
  s.name = "jsonb_accessor".freeze
  s.version = "1.4.2".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Michael Crismali".freeze, "Joe Hirn".freeze, "Jason Haruska".freeze]
  s.bindir = "exe".freeze
  s.date = "1980-01-02"
  s.description = "Adds typed jsonb backed fields to your ActiveRecord models.".freeze
  s.email = ["michael@crismali.com".freeze, "joe@devmynd.com".freeze, "jason@haruska.com".freeze]
  s.homepage = "https://github.com/madeintandem/jsonb_accessor".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3".freeze)
  s.rubygems_version = "3.6.7".freeze
  s.summary = "Adds typed jsonb backed fields to your ActiveRecord models.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<activerecord>.freeze, [">= 6.1".freeze])
  s.add_runtime_dependency(%q<activesupport>.freeze, [">= 6.1".freeze])
  s.add_runtime_dependency(%q<pg>.freeze, [">= 0.18.1".freeze])
  s.add_development_dependency(%q<awesome_print>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<benchmark>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<database_cleaner-active_record>.freeze, [">= 2.1".freeze])
  s.add_development_dependency(%q<ostruct>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<pry>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<pry-doc>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<pry-nav>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<psych>.freeze, [">= 3".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 12.3.3".freeze])
  s.add_development_dependency(%q<rspec>.freeze, [">= 3.6.0".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, [">= 1.0".freeze])
end
