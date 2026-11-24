# -*- encoding: utf-8 -*-
# stub: re2 2.27.0 x86_64-linux-gnu lib

Gem::Specification.new do |s|
  s.name = "re2".freeze
  s.version = "2.27.0".freeze
  s.platform = "x86_64-linux-gnu".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 3.3.22".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Paul Mucur".freeze, "Stan Hu".freeze]
  s.date = "1980-01-02"
  s.description = "Ruby bindings to RE2, \"a fast, safe, thread-friendly alternative to backtracking regular expression engines like those used in PCRE, Perl, and Python\".".freeze
  s.homepage = "https://github.com/mudge/re2".freeze
  s.licenses = ["BSD-3-Clause".freeze]
  s.required_ruby_version = Gem::Requirement.new([">= 3.1".freeze, "< 4.1.dev".freeze])
  s.rubygems_version = "4.0.3".freeze
  s.summary = "Ruby bindings to RE2.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<rake-compiler>.freeze, ["~> 1.3.1".freeze])
  s.add_development_dependency(%q<rake-compiler-dock>.freeze, ["~> 1.11.0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.2".freeze])
end
