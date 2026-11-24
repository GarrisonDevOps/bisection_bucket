# -*- encoding: utf-8 -*-
# stub: truncato 0.7.13 ruby lib

Gem::Specification.new do |s|
  s.name = "truncato".freeze
  s.version = "0.7.13".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "allowed_push_host" => "https://rubygems.org" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Jorge Manrubia".freeze]
  s.date = "2013-09-10"
  s.description = "Ruby tool for truncating HTML strings keeping a valid HTML markup".freeze
  s.email = "jorge.manrubia@gmail.com".freeze
  s.extra_rdoc_files = ["LICENSE.txt".freeze, "README.md".freeze]
  s.files = ["LICENSE.txt".freeze, "README.md".freeze]
  s.homepage = "https://github.com/jorgemanrubia/truncato".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "3.6.2".freeze
  s.summary = "A tool for truncating HTML strings efficiently".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<nokogiri>.freeze, [">= 1.7.0".freeze, "<= 2.0".freeze])
  s.add_runtime_dependency(%q<htmlentities>.freeze, ["~> 4.3.1".freeze])
  s.add_development_dependency(%q<rspec>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0".freeze])
end
