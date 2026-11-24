# -*- encoding: utf-8 -*-
# stub: grape_logging 3.0.1 ruby lib

Gem::Specification.new do |s|
  s.name = "grape_logging".freeze
  s.version = "3.0.1".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["aserafin".freeze, "Sami Samhuri".freeze]
  s.bindir = "exe".freeze
  s.date = "1980-01-02"
  s.description = "This gem provides simple request logging for Grape with just few lines of code you have to put in your project! In return you will get response codes, paths, parameters and more!".freeze
  s.email = ["adrian@softmad.pl".freeze, "sami@samhuri.net".freeze]
  s.homepage = "http://github.com/aserafin/grape_logging".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "3.6.9".freeze
  s.summary = "Out of the box request logging for Grape!".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<grape>.freeze, [">= 2.4.0".freeze])
  s.add_runtime_dependency(%q<rack>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<zeitwerk>.freeze, [">= 0".freeze])
end
