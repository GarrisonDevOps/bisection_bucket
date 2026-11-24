# -*- encoding: utf-8 -*-
# stub: omniauth-oauth2-generic 0.2.8 ruby lib

Gem::Specification.new do |s|
  s.name = "omniauth-oauth2-generic".freeze
  s.version = "0.2.8".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Satorix".freeze]
  s.date = "2020-09-14"
  s.description = "Generic, Configurable OmniAuth Strategy for OAuth2 providers".freeze
  s.email = ["satorix@iexposure.com".freeze]
  s.homepage = "https://gitlab.com/satorix/omniauth-oauth2-generic".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 1.9".freeze)
  s.rubygems_version = "3.0.3".freeze
  s.summary = "Generic, Configurable OmniAuth Strategy for OAuth2 providers".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<omniauth-oauth2>.freeze, ["~> 1.0".freeze])
  s.add_runtime_dependency(%q<rake>.freeze, [">= 0".freeze])
end
