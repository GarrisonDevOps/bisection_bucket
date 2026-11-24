# -*- encoding: utf-8 -*-
# stub: omniauth-atlassian-oauth2 0.2.0 ruby lib

Gem::Specification.new do |s|
  s.name = "omniauth-atlassian-oauth2".freeze
  s.version = "0.2.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Ben Standefer".freeze]
  s.date = "2019-03-02"
  s.description = "An Atlassian OAuth2 strategy for OmniAuth 1.x. This allows you to login to Atlassian with your ruby app.".freeze
  s.email = ["benstandefer@gmail.com".freeze]
  s.homepage = "https://github.com/aguynamedben/omniauth-atlassian-oauth2".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.1".freeze)
  s.rubygems_version = "2.5.2".freeze
  s.summary = "An Atlassian OAuth2 strategy for OmniAuth 1.x".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<omniauth>.freeze, [">= 1.1.1".freeze])
  s.add_runtime_dependency(%q<omniauth-oauth2>.freeze, [">= 1.5".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 12.0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.6".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, ["~> 0.49".freeze])
end
