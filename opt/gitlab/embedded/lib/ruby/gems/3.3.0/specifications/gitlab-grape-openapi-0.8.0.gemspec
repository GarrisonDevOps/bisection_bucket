# -*- encoding: utf-8 -*-
# stub: gitlab-grape-openapi 0.8.0 ruby lib

Gem::Specification.new do |s|
  s.name = "gitlab-grape-openapi".freeze
  s.version = "0.8.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://gitlab.com/gitlab-org/ruby/gems/gitlab-grape-openapi/-/issues", "changelog_uri" => "https://gitlab.com/gitlab-org/ruby/gems/gitlab-grape-openapi/-/blob/main/CHANGELOG.md", "homepage_uri" => "https://gitlab.com/gitlab-org/ruby/gems/gitlab-grape-openapi", "rubygems_mfa_required" => "true", "source_code_uri" => "https://gitlab.com/gitlab-org/ruby/gems/gitlab-grape-openapi" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["group::api".freeze]
  s.date = "2026-10-02"
  s.description = "A Ruby gem that introspects Grape API definitions and generates OpenAPI 3.0 specification files".freeze
  s.email = ["engineering@gitlab.com".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/ruby/gems/gitlab-grape-openapi".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.2.0".freeze)
  s.rubygems_version = "3.5.22".freeze
  s.summary = "Generate OpenAPI 3.0 specifications from Grape APIs".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<grape>.freeze, [">= 2.4".freeze, "< 3.3".freeze])
  s.add_runtime_dependency(%q<grape-entity>.freeze, ["~> 1.0".freeze])
  s.add_runtime_dependency(%q<js_regex>.freeze, ["~> 3.8".freeze])
  s.add_development_dependency(%q<gitlab-styles>.freeze, ["~> 13.1".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 13.0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.0".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, ["~> 1.71".freeze])
  s.add_development_dependency(%q<rubocop-rspec>.freeze, ["~> 3.0".freeze])
end
