# -*- encoding: utf-8 -*-
# stub: click_house-client 0.12.0 ruby lib

Gem::Specification.new do |s|
  s.name = "click_house-client".freeze
  s.version = "0.12.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["group::optimize".freeze]
  s.date = "2026-08-04"
  s.description = "This Gem provides a simple way to query ClickHouse databases using the HTTP interface.".freeze
  s.email = ["engineering@gitlab.com".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/ruby/gems/clickhouse-client".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.1".freeze)
  s.rubygems_version = "3.5.22".freeze
  s.summary = "GitLab's client to interact with ClickHouse".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<activerecord>.freeze, [">= 7.0".freeze, "< 9.0".freeze])
  s.add_runtime_dependency(%q<activesupport>.freeze, [">= 7.0".freeze, "< 9.0".freeze])
  s.add_runtime_dependency(%q<addressable>.freeze, ["~> 2.8".freeze])
  s.add_runtime_dependency(%q<json>.freeze, ["~> 2.7".freeze])
  s.add_development_dependency(%q<byebug>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<gitlab-styles>.freeze, ["~> 12.0.1".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 13.0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.0".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rubocop-rspec>.freeze, [">= 0".freeze])
end
