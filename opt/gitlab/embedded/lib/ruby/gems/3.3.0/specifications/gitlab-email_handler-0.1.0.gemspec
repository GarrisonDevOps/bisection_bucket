# -*- encoding: utf-8 -*-
# stub: gitlab-email_handler 0.1.0 ruby lib

Gem::Specification.new do |s|
  s.name = "gitlab-email_handler".freeze
  s.version = "0.1.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "changelog_uri" => "https://gitlab.com/gitlab-org/ruby/gems/gitlab-email_handler/-/releases", "rubygems_mfa_required" => "true", "source_code_uri" => "https://gitlab.com/gitlab-org/ruby/gems/gitlab-email_handler" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["group::project management".freeze]
  s.date = "2026-10-19"
  s.description = "Parses incoming email keys to identify the target handler and the resource (project, namespace, or route) that owns the email.".freeze
  s.email = ["engineering@gitlab.com".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/ruby/gems/gitlab-email_handler".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.2".freeze)
  s.rubygems_version = "3.5.22".freeze
  s.summary = "Incoming email identification for GitLab".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<gitlab-styles>.freeze, ["~> 14.0".freeze])
  s.add_development_dependency(%q<mail>.freeze, ["~> 2.8".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.0".freeze])
end
