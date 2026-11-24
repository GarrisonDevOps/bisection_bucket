# frozen_string_literal: true

require_relative "lib/declarative_enum/version"

Gem::Specification.new do |spec|
  spec.name = "gitlab-declarative_enum"
  spec.version = DeclarativeEnum::Version::VERSION
  spec.authors = ["group::threat insights"]
  spec.email = ["engineering@gitlab.com"]

  spec.summary = "Declarative enum definitions"
  spec.description = "Provides a DSL to declare enum values, their numeric representation and descriptions."
  spec.homepage = "https://gitlab.com/gitlab-org/gitlab/-/tree/master/gems/gitlab-declarative_enum"
  spec.license = 'MIT'
  spec.required_ruby_version = ">= 3.0"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir['lib/**/*.rb']
  spec.require_paths = ["lib"]

  spec.add_development_dependency "gitlab-styles", "~> 14.0"
  spec.add_development_dependency "pry"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "rubocop", "~> 1.50"
  spec.add_development_dependency "rubocop-rspec", "~> 3.0"
end
