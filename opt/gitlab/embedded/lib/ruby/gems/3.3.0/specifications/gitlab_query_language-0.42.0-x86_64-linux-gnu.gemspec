# -*- encoding: utf-8 -*-
# stub: gitlab_query_language 0.42.0 x86_64-linux-gnu lib

Gem::Specification.new do |s|
  s.name = "gitlab_query_language".freeze
  s.version = "0.42.0".freeze
  s.platform = "x86_64-linux-gnu".freeze

  s.required_rubygems_version = Gem::Requirement.new([">= 3.3.11".freeze, ">= 3.3.22".freeze]) if s.respond_to? :required_rubygems_version=
  s.metadata = { "changelog_uri" => "https://gitlab.com/gitlab-org/glql/-/tree/main/glql_rb/-/releases", "homepage_uri" => "https://gitlab.com/gitlab-org/glql/-/tree/main/glql_rb", "source_code_uri" => "https://gitlab.com/gitlab-org/glql/-/tree/main/glql_rb" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Himanshu Kapoor".freeze, "Daniele Rossetti".freeze]
  s.date = "2026-10-20"
  s.description = "A library to compile GitLab Query Language (GLQL) queries to GraphQL".freeze
  s.email = ["hkapoor@gitlab.com".freeze, "drossetti@gitlab.com".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/glql/-/tree/main/glql_rb".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new([">= 3.2".freeze, "< 3.5.dev".freeze])
  s.rubygems_version = "3.5.23".freeze
  s.summary = "GitLab Query Language compiler".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<rb_sys>.freeze, ["~> 0.9.91".freeze])
end
