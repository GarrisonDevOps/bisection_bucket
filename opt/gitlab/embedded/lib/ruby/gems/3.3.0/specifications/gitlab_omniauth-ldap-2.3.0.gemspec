# -*- encoding: utf-8 -*-
# stub: gitlab_omniauth-ldap 2.3.0 ruby lib

Gem::Specification.new do |s|
  s.name = "gitlab_omniauth-ldap".freeze
  s.version = "2.3.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Ping Yu".freeze]
  s.date = "2025-08-20"
  s.description = "A LDAP strategy for OmniAuth.".freeze
  s.email = ["ping@intridea.com".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/omniauth-ldap".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "3.5.22".freeze
  s.summary = "A LDAP strategy for OmniAuth.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<omniauth>.freeze, [">= 1.3".freeze, "< 3".freeze])
  s.add_runtime_dependency(%q<net-ldap>.freeze, ["~> 0.16".freeze])
  s.add_runtime_dependency(%q<pyu-ruby-sasl>.freeze, [">= 0.0.3.3".freeze, "< 0.1".freeze])
  s.add_runtime_dependency(%q<rubyntlm>.freeze, ["~> 0.5".freeze])
  s.add_development_dependency(%q<rspec>.freeze, [">= 2.12".freeze])
  s.add_development_dependency(%q<pry>.freeze, [">= 0.9".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 10.0".freeze])
  s.add_development_dependency(%q<rack-test>.freeze, [">= 0.6".freeze])
end
