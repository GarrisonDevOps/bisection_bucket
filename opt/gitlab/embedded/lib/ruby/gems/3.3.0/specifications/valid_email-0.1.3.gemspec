# -*- encoding: utf-8 -*-
# stub: valid_email 0.1.3 ruby lib

Gem::Specification.new do |s|
  s.name = "valid_email".freeze
  s.version = "0.1.3".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Ramihajamalala Hery".freeze]
  s.date = "2019-05-24"
  s.description = "ActiveModel Validation for email".freeze
  s.email = ["hery@rails-royce.org".freeze]
  s.homepage = "https://github.com/hallelujah/valid_email".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "2.7.6".freeze
  s.summary = "ActiveModel Validation for email".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<rspec>.freeze, ["~> 2.99".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["< 11.0".freeze])
  s.add_runtime_dependency(%q<mail>.freeze, [">= 2.6.1".freeze])
  s.add_runtime_dependency(%q<activemodel>.freeze, [">= 0".freeze])
end
