# -*- encoding: utf-8 -*-
# stub: jaeger-client 1.1.0 ruby lib

Gem::Specification.new do |s|
  s.name = "jaeger-client".freeze
  s.version = "1.1.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["SaleMove TechMovers".freeze]
  s.date = "2020-08-21"
  s.description = "".freeze
  s.email = ["techmovers@salemove.com".freeze]
  s.homepage = "https://github.com/salemove/jaeger-client-ruby".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "3.0.3".freeze
  s.summary = "OpenTracing Tracer implementation for Jaeger in Ruby".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<bundler>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 10.0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.0".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, ["~> 0.54.0".freeze])
  s.add_development_dependency(%q<rubocop-rspec>.freeze, ["~> 1.24.0".freeze])
  s.add_development_dependency(%q<timecop>.freeze, ["~> 0.9".freeze])
  s.add_development_dependency(%q<webmock>.freeze, ["~> 3.4.2".freeze])
  s.add_runtime_dependency(%q<opentracing>.freeze, ["~> 0.3".freeze])
  s.add_runtime_dependency(%q<thrift>.freeze, [">= 0".freeze])
end
