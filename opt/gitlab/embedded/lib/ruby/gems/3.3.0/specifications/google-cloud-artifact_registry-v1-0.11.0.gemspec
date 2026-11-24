# -*- encoding: utf-8 -*-
# stub: google-cloud-artifact_registry-v1 0.11.0 ruby lib

Gem::Specification.new do |s|
  s.name = "google-cloud-artifact_registry-v1".freeze
  s.version = "0.11.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Google LLC".freeze]
  s.date = "2023-10-27"
  s.description = "Artifact Registry stores and manages build artifacts in a scalable and integrated service built on Google infrastructure. Note that google-cloud-artifact_registry-v1 is a version-specific client library. For most uses, we recommend installing the main client library google-cloud-artifact_registry instead. See the readme for more details.".freeze
  s.email = "googleapis-packages@google.com".freeze
  s.homepage = "https://github.com/googleapis/google-cloud-ruby".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.6".freeze)
  s.rubygems_version = "3.4.19".freeze
  s.summary = "Store and manage build artifacts in a scalable and integrated service built on Google infrastructure.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<gapic-common>.freeze, [">= 0.20.0".freeze, "< 2.a".freeze])
  s.add_runtime_dependency(%q<google-cloud-errors>.freeze, ["~> 1.0".freeze])
  s.add_runtime_dependency(%q<google-cloud-location>.freeze, [">= 0.4".freeze, "< 2.a".freeze])
  s.add_runtime_dependency(%q<grpc-google-iam-v1>.freeze, ["~> 1.1".freeze])
  s.add_development_dependency(%q<google-style>.freeze, ["~> 1.26.3".freeze])
  s.add_development_dependency(%q<minitest>.freeze, ["~> 5.16".freeze])
  s.add_development_dependency(%q<minitest-focus>.freeze, ["~> 1.1".freeze])
  s.add_development_dependency(%q<minitest-rg>.freeze, ["~> 5.2".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 13.0".freeze])
  s.add_development_dependency(%q<redcarpet>.freeze, ["~> 3.0".freeze])
  s.add_development_dependency(%q<simplecov>.freeze, ["~> 0.18".freeze])
  s.add_development_dependency(%q<yard>.freeze, ["~> 0.9".freeze])
end
