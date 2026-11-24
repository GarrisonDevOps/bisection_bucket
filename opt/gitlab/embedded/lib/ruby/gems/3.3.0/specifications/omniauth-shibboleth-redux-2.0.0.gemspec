# -*- encoding: utf-8 -*-
# stub: omniauth-shibboleth-redux 2.0.0 ruby lib

Gem::Specification.new do |s|
  s.name = "omniauth-shibboleth-redux".freeze
  s.version = "2.0.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Bobby McDonald".freeze, "Toyokazu Akiyama".freeze]
  s.date = "2023-03-20"
  s.description = "OmniAuth Shibboleth strategies for OmniAuth 2.x".freeze
  s.email = ["bobbymcwho@gmail.com".freeze, "toyokazu@gmail.com".freeze]
  s.homepage = "".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "3.2.32".freeze
  s.summary = "OmniAuth Shibboleth strategies for OmniAuth 2.x".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<omniauth>.freeze, [">= 2.0.0".freeze])
  s.add_development_dependency(%q<rack-test>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rack-session>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, [">= 2.8".freeze])
end
