# -*- encoding: utf-8 -*-
# stub: gitlab-security_report_schemas 0.2.1.min15.0.0.max15.2.4 ruby lib

Gem::Specification.new do |s|
  s.name = "gitlab-security_report_schemas".freeze
  s.version = "0.2.1.min15.0.0.max15.2.4".freeze

  s.required_rubygems_version = Gem::Requirement.new("> 1.3.1".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "homepage_uri" => "https://gitlab.com/gitlab-org/ruby/gems/gitlab-security_report_schemas" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["GitLab".freeze]
  s.bindir = "exe".freeze
  s.date = "2026-08-11"
  s.email = ["gitlab_rubygems@gitlab.com".freeze]
  s.executables = ["security-report-schemas".freeze]
  s.files = ["exe/security-report-schemas".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/ruby/gems/gitlab-security_report_schemas".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.2.0".freeze)
  s.rubygems_version = "3.4.19".freeze
  s.summary = "Ruby gem for GitLab security report JSON schemas".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<activesupport>.freeze, [">= 6".freeze, "< 8.2".freeze])
  s.add_runtime_dependency(%q<json_schemer>.freeze, ["~> 2.4.0".freeze])
  s.add_runtime_dependency(%q<mutex_m>.freeze, ["~> 0.3.0".freeze])
end
