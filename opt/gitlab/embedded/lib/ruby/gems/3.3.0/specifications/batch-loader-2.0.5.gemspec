# -*- encoding: utf-8 -*-
# stub: batch-loader 2.0.5 ruby lib

Gem::Specification.new do |s|
  s.name = "batch-loader".freeze
  s.version = "2.0.5".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["exAspArk".freeze]
  s.bindir = "exe".freeze
  s.date = "2024-04-24"
  s.description = "Powerful tool to avoid N+1 DB or HTTP queries".freeze
  s.email = ["exaspark@gmail.com".freeze]
  s.homepage = "https://github.com/exAspArk/batch-loader".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.1.0".freeze)
  s.rubygems_version = "3.4.19".freeze
  s.summary = "Powerful tool to avoid N+1 DB or HTTP queries".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<bundler>.freeze, ["~> 2.0".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 13.0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.0".freeze])
  s.add_development_dependency(%q<graphql>.freeze, ["~> 1.8".freeze])
  s.add_development_dependency(%q<pry>.freeze, ["~> 0.14".freeze])
  s.add_development_dependency(%q<benchmark-ips>.freeze, ["~> 2.7".freeze])
  s.add_development_dependency(%q<ruby-prof>.freeze, ["~> 0.16".freeze])
end
