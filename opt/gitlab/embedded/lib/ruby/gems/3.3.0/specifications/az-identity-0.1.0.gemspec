# -*- encoding: utf-8 -*-
# stub: az-identity 0.1.0 ruby lib

Gem::Specification.new do |s|
  s.name = "az-identity".freeze
  s.version = "0.1.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "rubygems_mfa_required" => "true" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["GitLab".freeze]
  s.date = "1980-01-02"
  s.description = "Credential acquisition for Azure services using workload identity or managed identity".freeze
  s.homepage = "https://gitlab.com/gitlab-org/ruby/gems/az-identity".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.0.0".freeze)
  s.rubygems_version = "3.7.2".freeze
  s.summary = "Azure identity and authentication library for Ruby".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<base64>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<faraday>.freeze, ["~> 2.0".freeze])
end
