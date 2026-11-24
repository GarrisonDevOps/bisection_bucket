# -*- encoding: utf-8 -*-
# stub: fog-local 0.9.0 ruby lib

Gem::Specification.new do |s|
  s.name = "fog-local".freeze
  s.version = "0.9.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Wesley Beary".freeze, "Ville Lautanala".freeze]
  s.date = "2025-03-20"
  s.description = "This library can be used as a module for `fog` or as standalone provider\n                       to use local filesystem storage.".freeze
  s.email = ["geemus@gmail.com".freeze, "lautis@gmail.com".freeze]
  s.homepage = "https://github.com/fog/fog-local".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "3.5.18".freeze
  s.summary = "Module for the 'fog' gem to support local filesystem storage.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<bundler>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 12.3.3".freeze])
  s.add_development_dependency(%q<shindo>.freeze, ["~> 0.3".freeze])
  s.add_runtime_dependency(%q<fog-core>.freeze, [">= 1.27".freeze, "< 3.0".freeze])
end
