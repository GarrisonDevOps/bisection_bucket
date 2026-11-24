# -*- encoding: utf-8 -*-
# stub: state_machines 0.100.4 ruby lib

Gem::Specification.new do |s|
  s.name = "state_machines".freeze
  s.version = "0.100.4".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "changelog_uri" => "https://github.com/state-machines/state_machines/blob/master/CHANGELOG.md", "homepage_uri" => "https://github.com/state-machines/state_machines", "rubygems_mfa_required" => "true", "source_code_uri" => "https://github.com/state-machines/state_machines" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Abdelkader Boudih".freeze, "Aaron Pfeifer".freeze]
  s.date = "1980-01-02"
  s.description = "Adds support for creating state machines for attributes on any Ruby class".freeze
  s.email = ["terminale@gmail.com".freeze]
  s.homepage = "https://github.com/state-machines/state_machines".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.2.0".freeze)
  s.rubygems_version = "3.6.9".freeze
  s.summary = "State machines for attributes".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<bundler>.freeze, [">= 1.7.6".freeze])
  s.add_development_dependency(%q<minitest>.freeze, [">= 5.4".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0".freeze])
end
