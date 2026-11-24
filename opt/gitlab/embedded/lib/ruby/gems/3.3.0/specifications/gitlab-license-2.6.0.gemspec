# -*- encoding: utf-8 -*-
# stub: gitlab-license 2.6.0 ruby lib

Gem::Specification.new do |s|
  s.name = "gitlab-license".freeze
  s.version = "2.6.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Douwe Maan".freeze, "Stan Hu".freeze, "Tyler Amos".freeze]
  s.bindir = "exe".freeze
  s.date = "2024-11-14"
  s.email = ["douwe@gitlab.com".freeze, "stanhu@gitlab.com".freeze, "tamos@gitlab.com".freeze]
  s.homepage = "https://dev.gitlab.org/gitlab/gitlab-license".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.7.0".freeze)
  s.rubygems_version = "3.1.6".freeze
  s.summary = "gitlab-license helps you generate, verify and enforce software licenses.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<bundler>.freeze, ["~> 2.4".freeze])
  s.add_development_dependency(%q<byebug>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 10.0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.9".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, ["~> 0.80.1".freeze])
  s.add_development_dependency(%q<rubocop-rspec>.freeze, ["~> 1.38.1".freeze])
end
