# -*- encoding: utf-8 -*-
# stub: tanuki_emoji 0.13.0 ruby lib

Gem::Specification.new do |s|
  s.name = "tanuki_emoji".freeze
  s.version = "0.13.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://gitlab.com/gitlab-org/ruby/gems/tanuki_emoji/-/issues", "changelog_uri" => "https://gitlab.com/gitlab-org/ruby/gems/tanuki_emoji/-/blob/main/CHANGELOG.md", "homepage_uri" => "https://gitlab.com/gitlab-org/ruby/gems/tanuki_emoji", "source_code_uri" => "https://gitlab.com/gitlab-org/ruby/gems/tanuki_emoji" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Gabriel Mazetto".freeze]
  s.date = "2024-10-29"
  s.description = "Tanuki Emoji provides Emoji character information and metadata with support for Noto Emoji resources as fallback".freeze
  s.email = ["brodock@gmail.com".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/ruby/gems/tanuki_emoji".freeze
  s.licenses = ["MIT".freeze, "Apache2".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.0.0".freeze)
  s.rubygems_version = "3.3.27".freeze
  s.summary = "Tanuki Emoji".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<i18n>.freeze, ["~> 1.14".freeze])
  s.add_development_dependency(%q<gitlab-dangerfiles>.freeze, ["~> 2.11.0".freeze])
  s.add_development_dependency(%q<gitlab-styles>.freeze, ["~> 12.0".freeze])
  s.add_development_dependency(%q<pry-byebug>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 13.0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.0".freeze])
  s.add_development_dependency(%q<rspec_junit_formatter>.freeze, ["~> 0.4.0".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, ["~> 1.62".freeze])
  s.add_development_dependency(%q<simplecov>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<simplecov-cobertura>.freeze, ["~> 1.4.2".freeze])
end
