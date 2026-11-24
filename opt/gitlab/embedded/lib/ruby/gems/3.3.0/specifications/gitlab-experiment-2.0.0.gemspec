# -*- encoding: utf-8 -*-
# stub: gitlab-experiment 2.0.0 ruby lib

Gem::Specification.new do |s|
  s.name = "gitlab-experiment".freeze
  s.version = "2.0.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["GitLab".freeze]
  s.date = "2026-07-22"
  s.email = ["gitlab_rubygems@gitlab.com".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/ruby/gems/gitlab-experiment".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.2".freeze)
  s.rubygems_version = "3.5.22".freeze
  s.summary = "GitLab experimentation library.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<activesupport>.freeze, [">= 3.0".freeze])
  s.add_runtime_dependency(%q<request_store>.freeze, [">= 1.0".freeze])
  s.add_development_dependency(%q<gitlab-dangerfiles>.freeze, ["~> 4.1.0".freeze])
  s.add_development_dependency(%q<gitlab-styles>.freeze, ["~> 12.0.1".freeze])
  s.add_development_dependency(%q<lefthook>.freeze, ["~> 1.4.7".freeze])
  s.add_development_dependency(%q<pry-byebug>.freeze, ["~> 3.10.1".freeze])
  s.add_development_dependency(%q<rubocop-rails>.freeze, ["~> 2.24.0".freeze])
  s.add_development_dependency(%q<rubocop-rspec>.freeze, ["~> 2.27.1".freeze])
  s.add_development_dependency(%q<flipper>.freeze, ["~> 0.26.2".freeze])
  s.add_development_dependency(%q<generator_spec>.freeze, ["~> 0.9.4".freeze])
  s.add_development_dependency(%q<rspec-parameterized-table_syntax>.freeze, ["~> 1.0.0".freeze])
  s.add_development_dependency(%q<rspec-rails>.freeze, ["~> 6.0.3".freeze])
  s.add_development_dependency(%q<simplecov-cobertura>.freeze, ["~> 3.1.0".freeze])
end
