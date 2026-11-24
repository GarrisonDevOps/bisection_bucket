# -*- encoding: utf-8 -*-
# stub: gitlab-sdk 0.3.1 ruby lib

Gem::Specification.new do |s|
  s.name = "gitlab-sdk".freeze
  s.version = "0.3.1".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "allowed_push_host" => "https://rubygems.org", "changelog_uri" => "https://gitlab.com/gitlab-org/analytics-section/product-analytics/gl-application-sdk-rb/-/releases", "homepage_uri" => "https://gitlab.com/gitlab-org/analytics-section/product-analytics/gl-application-sdk-rb", "source_code_uri" => "https://gitlab.com/gitlab-org/analytics-section/product-analytics/gl-application-sdk-rb" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["GitLab".freeze]
  s.bindir = "exe".freeze
  s.date = "2024-02-29"
  s.description = "Client side Ruby SDK for GitLab Application services".freeze
  s.email = ["gitlab_rubygems@gitlab.com".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/analytics-section/product-analytics/gl-application-sdk-rb".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.6.0".freeze)
  s.rubygems_version = "3.3.26".freeze
  s.summary = "Client side Ruby SDK for GitLab Application services".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<activesupport>.freeze, [">= 5.2.0".freeze])
  s.add_runtime_dependency(%q<rake>.freeze, ["~> 13.0".freeze])
  s.add_runtime_dependency(%q<snowplow-tracker>.freeze, ["~> 0.8.0".freeze])
  s.add_development_dependency(%q<gitlab-styles>.freeze, ["~> 10.0.0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.0".freeze])
  s.add_development_dependency(%q<webmock>.freeze, [">= 0".freeze])
end
