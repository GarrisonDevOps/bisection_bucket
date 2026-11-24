# -*- encoding: utf-8 -*-
# stub: gitlab-orbit-proto 1.2.1 ruby lib

Gem::Specification.new do |s|
  s.name = "gitlab-orbit-proto".freeze
  s.version = "1.2.1".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "allowed_push_host" => "https://rubygems.org", "source_code_uri" => "https://gitlab.com/gitlab-org/orbit/knowledge-graph" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["GitLab".freeze]
  s.date = "2026-11-10"
  s.email = ["engineering@gitlab.com".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/orbit/knowledge-graph".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.7".freeze)
  s.rubygems_version = "3.5.22".freeze
  s.summary = "Auto-generated gRPC client for the GitLab Orbit service".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<grpc>.freeze, ["~> 1.0".freeze])
end
