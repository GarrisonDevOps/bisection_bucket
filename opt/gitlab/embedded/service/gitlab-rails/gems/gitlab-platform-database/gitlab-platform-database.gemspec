# frozen_string_literal: true

require_relative "lib/gitlab/platform/database/version"

Gem::Specification.new do |spec|
  spec.name = "gitlab-platform-database"
  spec.version = Gitlab::Platform::Database::VERSION
  spec.authors = ["group::tenant scale"]
  spec.email = ["engineering@gitlab.com"]

  spec.summary = "GitLab database platform libraries"
  spec.description = "The database area of the gitlab-platform gem family, extracted from " \
    "lib/gitlab/database/ in the GitLab Rails monolith. Constants keep their original " \
    "Gitlab::Database:: names and lib/gitlab/database/ paths."
  spec.homepage = "https://gitlab.com/gitlab-org/gitlab/-/tree/master/gems/gitlab-platform-database"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir["lib/**/*.rb"]
  spec.require_paths = ["lib"]

  spec.add_dependency "activerecord", ">= 7.2"

  spec.add_development_dependency "gitlab-styles", "~> 14.1"
  spec.add_development_dependency "rspec", "~> 3.13"
  spec.add_development_dependency "rspec-parameterized", "~> 1.0"
end
