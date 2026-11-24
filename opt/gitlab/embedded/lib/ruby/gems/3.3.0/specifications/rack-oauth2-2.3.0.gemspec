# -*- encoding: utf-8 -*-
# stub: rack-oauth2 2.3.0 ruby lib

Gem::Specification.new do |s|
  s.name = "rack-oauth2".freeze
  s.version = "2.3.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["nov matake".freeze]
  s.date = "1980-01-02"
  s.description = "OAuth 2.0 Server & Client Library. Both Bearer token type are supported.".freeze
  s.email = "nov@matake.jp".freeze
  s.extra_rdoc_files = ["LICENSE".freeze, "README.rdoc".freeze]
  s.files = ["LICENSE".freeze, "README.rdoc".freeze]
  s.homepage = "https://github.com/nov/rack-oauth2".freeze
  s.licenses = ["MIT".freeze]
  s.rdoc_options = ["--charset=UTF-8".freeze]
  s.rubygems_version = "3.6.9".freeze
  s.summary = "OAuth 2.0 Server & Client Library - Both Bearer token type are supported".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<rack>.freeze, [">= 2.1.0".freeze])
  s.add_runtime_dependency(%q<faraday>.freeze, ["~> 2.0".freeze])
  s.add_runtime_dependency(%q<faraday-follow_redirects>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<activesupport>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<attr_required>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<json-jwt>.freeze, [">= 1.11.0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<simplecov>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rspec-its>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<webmock>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rexml>.freeze, [">= 0".freeze])
end
