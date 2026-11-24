# -*- encoding: utf-8 -*-
# stub: redis-cloud-auth 0.1.1 ruby lib

Gem::Specification.new do |s|
  s.name = "redis-cloud-auth".freeze
  s.version = "0.1.1".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "rubygems_mfa_required" => "true" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["GitLab".freeze]
  s.date = "2026-11-06"
  s.description = "Pluggable credentials providers (Microsoft Entra, Amazon ElastiCache IAM, ...) that authenticate Redis connections with short-lived tokens, plus a redis-client middleware that re-authenticates long-lived connections before the token expires.".freeze
  s.homepage = "https://gitlab.com/gitlab-org/ruby/gems/redis-cloud-auth".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.1".freeze)
  s.rubygems_version = "3.5.22".freeze
  s.summary = "Rotating-token (cloud identity) authentication for Redis via redis-client middleware".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<redis-client>.freeze, [">= 0.14".freeze])
  s.add_runtime_dependency(%q<logger>.freeze, [">= 0".freeze])
end
