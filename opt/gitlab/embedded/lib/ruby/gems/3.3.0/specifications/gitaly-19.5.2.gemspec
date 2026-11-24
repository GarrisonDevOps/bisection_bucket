# -*- encoding: utf-8 -*-
# stub: gitaly 19.5.2 ruby ruby/proto

Gem::Specification.new do |s|
  s.name = "gitaly".freeze
  s.version = "19.5.2".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://gitlab.com/gitlab-org/gitaly/-/issues", "documentation_uri" => "https://gitlab-org.gitlab.io/gitaly", "homepage_uri" => "https://gitlab.com/gitlab-org/gitaly", "source_code_uri" => "https://gitlab.com/gitlab-org/gitaly/-/tree/master/proto" } if s.respond_to? :metadata=
  s.require_paths = ["ruby/proto".freeze]
  s.authors = ["GitLab Engineering".freeze]
  s.date = "1980-01-02"
  s.description = "Auto-generated gRPC client for gitaly.\nTo publish new versions see https://gitlab.com/gitlab-org/gitaly/-/blob/master/doc/PROCESS.md#publishing-the-ruby-gem.".freeze
  s.email = ["engineering@gitlab.com".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/gitaly".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "3.6.9".freeze
  s.summary = "Auto-generated gRPC client for gitaly".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<grpc>.freeze, ["~> 1.0".freeze])
end
