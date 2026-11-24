# -*- encoding: utf-8 -*-
# stub: health_check 3.1.0 ruby lib

Gem::Specification.new do |s|
  s.name = "health_check".freeze
  s.version = "3.1.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Ian Heggie".freeze]
  s.date = "2021-05-25"
  s.description = "  \tSimple health check of Rails app for uptime monitoring with Pingdom, NewRelic, EngineYard etc.\n".freeze
  s.email = ["ian@heggie.biz".freeze]
  s.extra_rdoc_files = ["README.rdoc".freeze]
  s.files = ["README.rdoc".freeze]
  s.homepage = "https://github.com/ianheggie/health_check".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.2.2".freeze)
  s.rubygems_version = "3.2.15".freeze
  s.summary = "Simple health check of Rails app for uptime monitoring with Pingdom, NewRelic, EngineYard etc.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<railties>.freeze, [">= 5.0".freeze])
  s.add_development_dependency(%q<smarter_bundler>.freeze, [">= 0.1.0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0.8.3".freeze])
  s.add_development_dependency(%q<shoulda>.freeze, ["~> 2.11.0".freeze])
  s.add_development_dependency(%q<bundler>.freeze, [">= 1.2".freeze])
end
