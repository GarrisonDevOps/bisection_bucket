# -*- encoding: utf-8 -*-
# stub: webfinger 2.1.3 ruby lib

Gem::Specification.new do |s|
  s.name = "webfinger".freeze
  s.version = "2.1.3".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["nov matake".freeze]
  s.date = "2023-12-27"
  s.description = "Ruby WebFinger client library".freeze
  s.email = ["nov@matake.jp".freeze]
  s.homepage = "https://github.com/nov/webfinger".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "3.4.10".freeze
  s.summary = "Ruby WebFinger client library, following IETF WebFinger WG spec updates.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<faraday>.freeze, ["~> 2.0".freeze])
  s.add_runtime_dependency(%q<faraday-follow_redirects>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<activesupport>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rspec-its>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<simplecov>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<webmock>.freeze, [">= 1.6.2".freeze])
end
