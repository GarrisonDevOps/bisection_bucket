# -*- encoding: utf-8 -*-
# stub: gitlab-net-dns 0.15.0 ruby lib

Gem::Specification.new do |s|
  s.name = "gitlab-net-dns".freeze
  s.version = "0.15.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Marco Ceresa".freeze, "Simone Carletti".freeze]
  s.date = "2025-07-14"
  s.description = "Net::DNS is a pure Ruby DNS library, with a clean OO interface and an extensible API.".freeze
  s.email = ["ceresa@gmail.com".freeze, "weppos@weppos.net".freeze]
  s.extra_rdoc_files = ["LICENSE.txt".freeze]
  s.files = ["LICENSE.txt".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/gitlab-net-dns".freeze
  s.licenses = ["Ruby".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.0".freeze)
  s.rubygems_version = "3.6.2".freeze
  s.summary = "Pure Ruby DNS library.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<logger>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<mocha>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<yard>.freeze, [">= 0".freeze])
end
