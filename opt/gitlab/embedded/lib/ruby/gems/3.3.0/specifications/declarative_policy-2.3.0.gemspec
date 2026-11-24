# -*- encoding: utf-8 -*-
# stub: declarative_policy 2.3.0 ruby lib

Gem::Specification.new do |s|
  s.name = "declarative_policy".freeze
  s.version = "2.3.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "changelog_uri" => "https://gitlab.com/gitlab-org/ruby/gems/declarative-policy/-/releases", "homepage_uri" => "https://gitlab.com/gitlab-org/ruby/gems/declarative-policy", "rubygems_mfa_required" => "false", "source_code_uri" => "https://gitlab.com/gitlab-org/ruby/gems/declarative-policy" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["group::authorization".freeze]
  s.bindir = "exe".freeze
  s.date = "2026-10-26"
  s.description = "This library provides an authorization framework with a declarative DSL\n\nWith this library, you can write permission policies that are separate\nfrom business logic.\n\nThis library is in production use at GitLab.com\n".freeze
  s.email = ["engineering@gitlab.com".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/ruby/gems/declarative-policy".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.0.0".freeze)
  s.rubygems_version = "3.5.22".freeze
  s.summary = "An authorization library with a focus on declarative policy definitions.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<benchmark-ips>.freeze, ["~> 2.12".freeze])
  s.add_development_dependency(%q<gitlab-dangerfiles>.freeze, ["~> 3.8".freeze])
  s.add_development_dependency(%q<gitlab-styles>.freeze, ["~> 12.0".freeze])
  s.add_development_dependency(%q<pry-byebug>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 12.0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.10".freeze])
  s.add_development_dependency(%q<rspec-parameterized>.freeze, ["~> 1.0".freeze])
end
