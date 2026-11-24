# -*- encoding: utf-8 -*-
# stub: semver_dialects 4.1.3 ruby lib

Gem::Specification.new do |s|
  s.name = "semver_dialects".freeze
  s.version = "4.1.3".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "allowed_push_host" => "https://rubygems.org", "changelog_uri" => "https://gitlab.com/gitlab-org/ruby/gems/semver_dialects/-/blob/master/CHANGELOG.md", "homepage_uri" => "https://rubygems.org/gems/semver_dialects", "source_code_uri" => "https://gitlab.com/gitlab-org/ruby/gems/semver_dialects" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Julian Thome".freeze, "Isaac Dawson".freeze, "James Jonhson".freeze]
  s.bindir = "exe".freeze
  s.date = "2026-07-31"
  s.description = "This gem helps to parse, process and compare semantic versions for Maven, NPM, PHP, RubyGems and python packages.".freeze
  s.email = ["jthome@gitlab.com".freeze, "idawson@gitlab.com".freeze, "jjohnson@gitlab.com".freeze]
  s.homepage = "https://rubygems.org/gems/semver_dialects".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.2".freeze)
  s.rubygems_version = "3.4.19".freeze
  s.summary = "This gem provides utility function to process semantic versions expressed in different dialects.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<pastel>.freeze, ["~> 0.8.0".freeze])
  s.add_runtime_dependency(%q<thor>.freeze, ["~> 1.3".freeze])
  s.add_runtime_dependency(%q<deb_version>.freeze, ["~> 1.0.1".freeze])
  s.add_runtime_dependency(%q<tty-command>.freeze, ["~> 0.10.1".freeze])
  s.add_development_dependency(%q<unparser>.freeze, ["~> 0.6.13".freeze])
  s.add_development_dependency(%q<benchmark-ips>.freeze, ["~> 2.13".freeze])
  s.add_development_dependency(%q<bundler>.freeze, ["~> 2.4".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 12.3.3".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.0".freeze])
  s.add_development_dependency(%q<rspec-parameterized>.freeze, ["~> 1.0".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, ["~> 1.63".freeze])
  s.add_development_dependency(%q<simplecov>.freeze, ["~> 0.17.1".freeze])
end
