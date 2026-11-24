# frozen_string_literal: true

require_relative "lib/gitlab/git/version"

Gem::Specification.new do |spec|
  spec.name = "gitlab-git2"
  spec.version = Gitlab::Git::VERSION
  spec.authors = ["group::source code"]
  spec.email = ["engineering@gitlab.com"]

  spec.summary = "GitLab's Git layer and Gitaly client"
  spec.description = "Gitlab::Git and Gitlab::GitalyClient, to be extracted from the GitLab Rails monolith. " \
    "For now it holds only the test harness that runs the gem's specs against a real Gitaly server."
  spec.homepage = "https://gitlab.com/gitlab-org/gitlab/-/tree/master/gems/gitlab-git2"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.3"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir["lib/**/*.rb"]
  spec.require_paths = ["lib"]

  spec.add_dependency "gitaly", "~> 19.5.0"
  spec.add_dependency "grpc", "~> 1.81.0"

  spec.add_development_dependency "gitlab-styles", "~> 14.1"
  spec.add_development_dependency "rspec", "~> 3.13"
end
