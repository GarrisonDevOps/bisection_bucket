# frozen_string_literal: true

require_relative "lib/gitlab/diff/version"

Gem::Specification.new do |spec|
  spec.name = "gitlab-diff"
  spec.version = Gitlab::Diff::VERSION
  spec.authors = ["group::source code"]
  spec.email = ["engineering@gitlab.com"]

  spec.summary = "GitLab diff parsing and rendering"
  spec.description = "The diff parsing, inline and word diff, and diff formatting code of GitLab, " \
    "extracted from the GitLab Rails monolith. Contains no ActiveRecord: everything GitLab-specific " \
    "arrives through ports on Gitlab::Diff::Configuration. Constants keep their original names."
  spec.homepage = "https://gitlab.com/gitlab-org/gitlab/-/tree/master/gems/gitlab-diff"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.3"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir["lib/**/*.rb"]
  spec.require_paths = ["lib"]

  spec.add_dependency "activesupport", ">= 7.2"
  spec.add_dependency "diff_match_patch", "~> 0.1.0"
  spec.add_dependency "gitlab-utils", "~> 0.1"

  spec.add_development_dependency "gitlab-styles", "~> 14.1"
  spec.add_development_dependency "rspec", "~> 3.13"
  spec.add_development_dependency "rspec-parameterized", "~> 1.0"
end
