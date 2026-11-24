# -*- encoding: utf-8 -*-
# stub: googleapis-common-protos 1.7.0 ruby lib

Gem::Specification.new do |s|
  s.name = "googleapis-common-protos".freeze
  s.version = "1.7.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Google LLC".freeze]
  s.date = "2025-03-19"
  s.description = "Common gRPC and protocol buffer classes used in Google APIs".freeze
  s.email = ["googleapis-packages@google.com".freeze]
  s.homepage = "https://github.com/googleapis/common-protos-ruby".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.0".freeze)
  s.rubygems_version = "3.6.5".freeze
  s.summary = "Common gRPC and protocol buffer classes used in Google APIs".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<googleapis-common-protos-types>.freeze, ["~> 1.7".freeze])
  s.add_runtime_dependency(%q<google-protobuf>.freeze, [">= 3.18".freeze, "< 5.a".freeze])
  s.add_runtime_dependency(%q<grpc>.freeze, ["~> 1.41".freeze])
end
