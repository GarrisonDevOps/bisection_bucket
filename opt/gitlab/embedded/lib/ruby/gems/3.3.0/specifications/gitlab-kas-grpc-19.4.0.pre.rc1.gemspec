# -*- encoding: utf-8 -*-
# stub: gitlab-kas-grpc 19.4.0.pre.rc1 ruby lib

Gem::Specification.new do |s|
  s.name = "gitlab-kas-grpc".freeze
  s.version = "19.4.0.pre.rc1".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent/-/issues", "documentation_uri" => "https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent/-/tree/master/doc", "homepage_uri" => "https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent", "source_code_uri" => "https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent/-/tree/master" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Tiger Watson".freeze, "Timo Furrer".freeze, "Taka Nishida".freeze]
  s.date = "2026-08-20"
  s.email = ["twatson@gitlab.com".freeze, "tfurrer@gitlab.com".freeze, "tnishida@gitlab.com".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.3".freeze)
  s.rubygems_version = "3.5.22".freeze
  s.summary = "Auto-generated gRPC client for KAS".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<grpc>.freeze, ["~> 1.81".freeze])
  s.add_runtime_dependency(%q<google-protobuf>.freeze, [">= 3.25".freeze, "< 5.0".freeze])
end
