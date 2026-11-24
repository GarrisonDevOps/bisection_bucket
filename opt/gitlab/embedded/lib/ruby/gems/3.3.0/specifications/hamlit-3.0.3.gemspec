# -*- encoding: utf-8 -*-
# stub: hamlit 3.0.3 ruby lib
# stub: ext/hamlit/extconf.rb

Gem::Specification.new do |s|
  s.name = "hamlit".freeze
  s.version = "3.0.3".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Takashi Kokubun".freeze]
  s.bindir = "exe".freeze
  s.date = "2022-11-08"
  s.description = "High Performance Haml Implementation".freeze
  s.email = ["takashikkbn@gmail.com".freeze]
  s.executables = ["hamlit".freeze]
  s.extensions = ["ext/hamlit/extconf.rb".freeze]
  s.files = ["exe/hamlit".freeze, "ext/hamlit/extconf.rb".freeze]
  s.homepage = "https://github.com/k0kubun/hamlit".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.1.0".freeze)
  s.rubygems_version = "3.3.7".freeze
  s.summary = "High Performance Haml Implementation".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<temple>.freeze, [">= 0.8.2".freeze])
  s.add_runtime_dependency(%q<thor>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<tilt>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<benchmark_driver>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<bundler>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<erubi>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<haml>.freeze, [">= 5".freeze])
  s.add_development_dependency(%q<less>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<minitest-reporters>.freeze, ["~> 1.1".freeze])
  s.add_development_dependency(%q<rails>.freeze, [">= 4.0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake-compiler>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<sass>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<slim>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<string_template>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<unindent>.freeze, [">= 0".freeze])
end
