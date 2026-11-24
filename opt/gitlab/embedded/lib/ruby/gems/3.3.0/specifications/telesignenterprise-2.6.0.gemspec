# -*- encoding: utf-8 -*-
# stub: telesignenterprise 2.6.0 ruby lib

Gem::Specification.new do |s|
  s.name = "telesignenterprise".freeze
  s.version = "2.6.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["TeleSign".freeze]
  s.date = "2017-05-02"
  s.description = "TeleSign Enterprise Ruby SDK".freeze
  s.email = "support@telesign.com".freeze
  s.homepage = "http://rubygems.org/gems/telesign".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "3.4.10".freeze
  s.summary = "TeleSign Enterprise Ruby SDK".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<telesign>.freeze, ["~> 2.4.0".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 13.2".freeze])
  s.add_development_dependency(%q<uuid>.freeze, ["~> 2.3".freeze])
  s.add_development_dependency(%q<mocha>.freeze, ["~> 2.7".freeze])
  s.add_development_dependency(%q<webmock>.freeze, ["~> 3.24".freeze])
  s.add_development_dependency(%q<codecov>.freeze, ["~> 0.6.0".freeze])
  s.add_development_dependency(%q<simplecov>.freeze, ["~> 0.22.0".freeze])
  s.add_development_dependency(%q<test-unit>.freeze, ["~> 3.6".freeze])
end
