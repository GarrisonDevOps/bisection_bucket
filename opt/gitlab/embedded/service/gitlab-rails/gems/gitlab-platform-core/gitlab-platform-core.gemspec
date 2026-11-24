# frozen_string_literal: true

require_relative "lib/gitlab/platform/core/version"

Gem::Specification.new do |spec|
  spec.name = "gitlab-platform-core"
  spec.version = Gitlab::Platform::Core::VERSION
  spec.authors = ["group::tenant scale"]
  spec.email = ["engineering@gitlab.com"]

  spec.summary = "Cross-cutting GitLab platform libraries"
  spec.description = "Cross-cutting infrastructure extracted from the GitLab Rails monolith. " \
    "Broader in scope than gitlab-utils, which stays generic stateless helpers. " \
    "Constants keep their original Gitlab:: names and lib/gitlab/ paths."
  spec.homepage = "https://gitlab.com/gitlab-org/gitlab/-/tree/master/gems/gitlab-platform-core"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir["lib/**/*.rb"]
  spec.require_paths = ["lib"]

  spec.add_development_dependency "gitlab-styles", "~> 14.1"
  spec.add_development_dependency "rspec", "~> 3.13"
  spec.add_development_dependency "rspec-parameterized", "~> 1.0"
end
