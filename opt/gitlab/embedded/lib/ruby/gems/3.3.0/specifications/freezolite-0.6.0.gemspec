# -*- encoding: utf-8 -*-
# stub: freezolite 0.6.0 ruby lib

Gem::Specification.new do |s|
  s.name = "freezolite".freeze
  s.version = "0.6.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://github.com/ruby-next/freezolite/issues", "changelog_uri" => "https://github.com/ruby-next/freezolite/blob/master/CHANGELOG.md", "documentation_uri" => "https://github.com/ruby-next/freezolite", "homepage_uri" => "https://github.com/ruby-next/freezolite", "source_code_uri" => "https://github.com/ruby-next/freezolite" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Vladimir Dementyev".freeze]
  s.date = "2025-03-07"
  s.description = "Example description".freeze
  s.email = ["Vladimir Dementyev".freeze]
  s.homepage = "https://github.com/ruby-next/freezolite".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.7".freeze)
  s.rubygems_version = "3.4.19".freeze
  s.summary = "Example description".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<require-hooks>.freeze, ["~> 0.2".freeze])
  s.add_development_dependency(%q<bundler>.freeze, [">= 1.15".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 13.0".freeze])
  s.add_development_dependency(%q<minitest>.freeze, ["~> 5.0".freeze])
end
