# -*- encoding: utf-8 -*-
# stub: gitlab-cloud-connector 1.54.0 ruby lib

Gem::Specification.new do |s|
  s.name = "gitlab-cloud-connector".freeze
  s.version = "1.54.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "allowed_push_host" => "https://rubygems.org", "changelog_uri" => "https://gitlab.com/gitlab-org/cloud-connector/gitlab-cloud-connector/-/releases", "homepage_uri" => "https://gitlab.com/gitlab-org/cloud-connector/gitlab-cloud-connector", "source_code_uri" => "https://gitlab.com/gitlab-org/cloud-connector/gitlab-cloud-connector" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Nikola Milojevic".freeze]
  s.bindir = "exe".freeze
  s.date = "2026-09-22"
  s.description = "This gem provides common CloudConnector configuration and libraries for GitLab projects.".freeze
  s.email = ["nmilojevic@gitlab.com".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/cloud-connector/gitlab-cloud-connector".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.0.0".freeze)
  s.rubygems_version = "3.4.19".freeze
  s.summary = "GitLab cloud connector project.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<activesupport>.freeze, [">= 7.0".freeze])
  s.add_runtime_dependency(%q<jwt>.freeze, ["~> 2.10".freeze, ">= 2.10.3".freeze])
  s.add_development_dependency(%q<gitlab-styles>.freeze, ["~> 12.0.1".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 13.0.6".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.8".freeze])
end
