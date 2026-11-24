# -*- encoding: utf-8 -*-
# stub: state_machines-activerecord 0.100.0 ruby lib

Gem::Specification.new do |s|
  s.name = "state_machines-activerecord".freeze
  s.version = "0.100.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "rubygems_mfa_required" => "true" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Abdelkader Boudih".freeze, "Aaron Pfeifer".freeze]
  s.date = "1980-01-02"
  s.description = "Adds support for creating state machines for attributes on ActiveRecord".freeze
  s.email = ["terminale@gmail.com".freeze, "aaron@pluginaweek.org".freeze]
  s.homepage = "https://github.com/state-machines/state_machines-activerecord/".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.2".freeze)
  s.rubygems_version = "3.6.9".freeze
  s.summary = "State machines Active Record Integration".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<activerecord>.freeze, [">= 7.2".freeze])
  s.add_runtime_dependency(%q<state_machines-activemodel>.freeze, [">= 0.100.0".freeze])
  s.add_development_dependency(%q<appraisal>.freeze, [">= 1".freeze])
  s.add_development_dependency(%q<minitest>.freeze, [">= 5.4.0".freeze])
  s.add_development_dependency(%q<minitest-reporters>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 13.0".freeze])
  s.add_development_dependency(%q<sqlite3>.freeze, ["~> 1.3".freeze])
end
