# -*- encoding: utf-8 -*-
# stub: redis-cluster-client 0.17.1 ruby lib

Gem::Specification.new do |s|
  s.name = "redis-cluster-client".freeze
  s.version = "0.17.1".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "allowed_push_host" => "https://rubygems.org", "rubygems_mfa_required" => "true" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Taishi Kasuga".freeze]
  s.date = "1980-01-02"
  s.email = ["proxy0721@gmail.com".freeze]
  s.homepage = "https://github.com/redis-rb/redis-cluster-client".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.7.0".freeze)
  s.rubygems_version = "4.0.16".freeze
  s.summary = "Redis cluster-aware client for Ruby".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<redis-client>.freeze, ["~> 0.28".freeze])
end
