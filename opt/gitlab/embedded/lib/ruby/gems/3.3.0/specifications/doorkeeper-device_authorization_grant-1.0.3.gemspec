# -*- encoding: utf-8 -*-
# stub: doorkeeper-device_authorization_grant 1.0.3 ruby lib

Gem::Specification.new do |s|
  s.name = "doorkeeper-device_authorization_grant".freeze
  s.version = "1.0.3".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "changelog_uri" => "https://github.com/exop-group/doorkeeper-device_authorization_grant/blob/master/CHANGELOG.md", "homepage_uri" => "https://github.com/exop-group/doorkeeper-device_authorization_grant", "rubygems_mfa_required" => "true", "source_code_uri" => "https://github.com/exop-group/doorkeeper-device_authorization_grant" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["EXOP Group".freeze]
  s.date = "2023-04-11"
  s.description = "OAuth 2.0 Device Authorization Grant extension for Doorkeeper.".freeze
  s.email = ["opensource@exop-group.com".freeze]
  s.homepage = "https://github.com/exop-group/doorkeeper-device_authorization_grant".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.5".freeze)
  s.rubygems_version = "3.3.7".freeze
  s.summary = "OAuth 2.0 Device Authorization Grant extension for Doorkeeper.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<doorkeeper>.freeze, ["~> 5.5".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, ["~> 1.23".freeze])
  s.add_development_dependency(%q<rubocop-performance>.freeze, ["~> 1.12".freeze])
  s.add_development_dependency(%q<rubocop-rails>.freeze, ["~> 2.12".freeze])
  s.add_development_dependency(%q<simplecov>.freeze, ["~> 0.21.2".freeze])
  s.add_development_dependency(%q<sqlite3>.freeze, ["~> 1.4".freeze])
  s.add_development_dependency(%q<yard>.freeze, ["~> 0.9.27".freeze])
end
