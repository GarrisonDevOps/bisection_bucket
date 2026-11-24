# -*- encoding: utf-8 -*-
# stub: apnotic 1.8.0 ruby lib

Gem::Specification.new do |s|
  s.name = "apnotic".freeze
  s.version = "1.8.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Roberto Ostinelli".freeze]
  s.bindir = "exe".freeze
  s.date = "1980-01-02"
  s.email = ["roberto@ostinelli.net".freeze]
  s.homepage = "http://github.com/ostinelli/apnotic".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.2.0".freeze)
  s.rubygems_version = "3.7.1".freeze
  s.summary = "Apnotic is an Apple Push Notification gem able to provide instant feedback.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<net-http2>.freeze, [">= 0.18.3".freeze, "< 2".freeze])
  s.add_runtime_dependency(%q<connection_pool>.freeze, [">= 2".freeze, "< 4".freeze])
  s.add_runtime_dependency(%q<base64>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<bundler>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 13.3.1".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.0".freeze])
end
