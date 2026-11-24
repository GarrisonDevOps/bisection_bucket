# -*- encoding: utf-8 -*-
# stub: grape-path-helpers 2.1.0 ruby lib

Gem::Specification.new do |s|
  s.name = "grape-path-helpers".freeze
  s.version = "2.1.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Drew Blessing".freeze, "Harper Henn".freeze]
  s.date = "2026-08-05"
  s.description = "Route path helpers for Grape".freeze
  s.email = "".freeze
  s.homepage = "https://gitlab.com/gitlab-org/ruby/gems/grape-path-helpers".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.2".freeze)
  s.rubygems_version = "3.5.22".freeze
  s.summary = "Route path helpers for Grape".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<activesupport>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<grape>.freeze, [">= 2.0".freeze, "< 4".freeze])
  s.add_runtime_dependency(%q<rake>.freeze, ["> 12".freeze])
  s.add_runtime_dependency(%q<ruby2_keywords>.freeze, ["~> 0.0.2".freeze])
  s.add_development_dependency(%q<pry>.freeze, ["~> 0.11".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.7".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, ["~> 1.50".freeze])
end
