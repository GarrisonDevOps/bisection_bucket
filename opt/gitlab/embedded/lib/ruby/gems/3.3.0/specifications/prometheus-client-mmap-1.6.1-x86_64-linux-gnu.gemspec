# -*- encoding: utf-8 -*-
# stub: prometheus-client-mmap 1.6.1 x86_64-linux-gnu lib

Gem::Specification.new do |s|
  s.name = "prometheus-client-mmap".freeze
  s.version = "1.6.1".freeze
  s.platform = "x86_64-linux-gnu".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 3.3.22".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Tobias Schmidt".freeze, "Pawe\u0142 Chojnacki".freeze, "Stan Hu".freeze, "Will Chandler".freeze]
  s.date = "2026-08-05"
  s.email = ["ts@soundcloud.com".freeze, "pawel@gitlab.com".freeze, "stanhu@gmail.com".freeze, "wchandler@gitlab.com".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/prometheus-client-mmap".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.required_ruby_version = Gem::Requirement.new([">= 3.1".freeze, "< 4.1.dev".freeze])
  s.rubygems_version = "3.5.23".freeze
  s.summary = "A suite of instrumentation metric primitives that can be exposed through a web services interface.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<base64>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<bigdecimal>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<logger>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<rb_sys>.freeze, ["~> 0.9.128".freeze])
  s.add_development_dependency(%q<fuzzbert>.freeze, ["~> 1.0".freeze, ">= 1.0.4".freeze])
  s.add_development_dependency(%q<gem_publisher>.freeze, ["~> 1".freeze])
  s.add_development_dependency(%q<pry>.freeze, ["~> 0.12.2".freeze])
  s.add_development_dependency(%q<rake-compiler>.freeze, ["~> 1.3".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.2".freeze])
  s.add_development_dependency(%q<ruby-prof>.freeze, ["~> 1.7".freeze])
end
