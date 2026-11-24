# -*- encoding: utf-8 -*-
# stub: omniauth-auth0 3.1.1 ruby lib

Gem::Specification.new do |s|
  s.name = "omniauth-auth0".freeze
  s.version = "3.1.1".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Auth0".freeze]
  s.date = "2023-07-25"
  s.description = "Auth0 is an authentication broker that supports social identity providers as well as enterprise identity providers such as Active Directory, LDAP, Google Apps, Salesforce.\n\nOmniAuth is a library that standardizes multi-provider authentication for web applications. It was created to be powerful, flexible, and do as little as possible.\n\nomniauth-auth0 is the OmniAuth strategy for Auth0.\n".freeze
  s.email = ["info@auth0.com".freeze]
  s.homepage = "https://github.com/auth0/omniauth-auth0".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "3.4.10".freeze
  s.summary = "OmniAuth OAuth2 strategy for the Auth0 platform.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<omniauth>.freeze, ["~> 2".freeze])
  s.add_runtime_dependency(%q<omniauth-oauth2>.freeze, ["~> 1".freeze])
  s.add_development_dependency(%q<bundler>.freeze, [">= 0".freeze])
end
