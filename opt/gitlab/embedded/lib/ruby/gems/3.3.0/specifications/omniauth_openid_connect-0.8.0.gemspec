# -*- encoding: utf-8 -*-
# stub: omniauth_openid_connect 0.8.0 ruby lib

Gem::Specification.new do |s|
  s.name = "omniauth_openid_connect".freeze
  s.version = "0.8.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://github.com/omniauth/omniauth_openid_connect/issues", "changelog_uri" => "https://github.com/omniauth/omniauth_openid_connect/releases", "documentation_uri" => "https://github.com/omniauth/omniauth_openid_connect/tree/v0.8.0#readme", "rubygems_mfa_required" => "true", "source_code_uri" => "https://github.com/omniauth/omniauth_openid_connect/tree/v0.8.0" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["John Bohn".freeze, "Ilya Shcherbinin".freeze]
  s.date = "2024-07-04"
  s.description = "OpenID Connect Strategy for OmniAuth.".freeze
  s.email = ["jjbohn@gmail.com".freeze, "m0n9oose@gmail.com".freeze]
  s.homepage = "https://github.com/omniauth/omniauth_openid_connect".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "3.5.14".freeze
  s.summary = "OpenID Connect Strategy for OmniAuth".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<omniauth>.freeze, [">= 1.9".freeze, "< 3".freeze])
  s.add_runtime_dependency(%q<openid_connect>.freeze, ["~> 2.2".freeze])
  s.add_development_dependency(%q<faker>.freeze, ["~> 2.0".freeze])
  s.add_development_dependency(%q<guard>.freeze, ["~> 2.14".freeze])
  s.add_development_dependency(%q<guard-bundler>.freeze, ["~> 2.2".freeze])
  s.add_development_dependency(%q<guard-minitest>.freeze, ["~> 2.4".freeze])
  s.add_development_dependency(%q<minitest>.freeze, ["~> 5.20".freeze])
  s.add_development_dependency(%q<mocha>.freeze, ["~> 2.1".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 12.0".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, ["~> 1.12".freeze])
  s.add_development_dependency(%q<simplecov>.freeze, ["~> 0.21".freeze])
  s.add_development_dependency(%q<simplecov-lcov>.freeze, ["~> 0.8".freeze])
  s.add_development_dependency(%q<webmock>.freeze, ["~> 3.18".freeze])
end
