# -*- encoding: utf-8 -*-
# stub: circuitbox 2.0.0 ruby lib

Gem::Specification.new do |s|
  s.name = "circuitbox".freeze
  s.version = "2.0.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://github.com/yammer/circuitbox/issues", "changelog_uri" => "https://github.com/yammer/circuitbox/blob/main/CHANGELOG.md", "rubygems_mfa_required" => "true", "source_code_uri" => "https://github.com/yammer/circuitbox" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Fahim Ferdous".freeze, "Matthew Shafer".freeze]
  s.date = "2023-05-04"
  s.email = ["fahimfmf@gmail.com".freeze]
  s.homepage = "https://github.com/yammer/circuitbox".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.6.0".freeze)
  s.rubygems_version = "3.1.6".freeze
  s.summary = "A robust circuit breaker that manages failing external services.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<bundler>.freeze, ["> 2.0".freeze])
  s.add_development_dependency(%q<excon>.freeze, ["~> 0.71".freeze])
  s.add_development_dependency(%q<faraday>.freeze, [">= 0.17".freeze])
  s.add_development_dependency(%q<gimme>.freeze, ["~> 0.5".freeze])
  s.add_development_dependency(%q<minitest>.freeze, ["~> 5.14".freeze])
  s.add_development_dependency(%q<minitest-excludes>.freeze, ["~> 2.0".freeze])
  s.add_development_dependency(%q<mocha>.freeze, ["~> 1.12".freeze])
  s.add_development_dependency(%q<moneta>.freeze, ["~> 1.0".freeze])
  s.add_development_dependency(%q<rack>.freeze, ["~> 2.0".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 13.0".freeze])
  s.add_development_dependency(%q<timecop>.freeze, ["~> 0.9".freeze])
  s.add_development_dependency(%q<typhoeus>.freeze, ["~> 1.4".freeze])
  s.add_development_dependency(%q<webrick>.freeze, ["~> 1.7".freeze])
  s.add_development_dependency(%q<yard>.freeze, ["~> 0.9.26".freeze])
end
