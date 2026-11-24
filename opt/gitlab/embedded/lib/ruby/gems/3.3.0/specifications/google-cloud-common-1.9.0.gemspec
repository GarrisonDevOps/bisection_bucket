# -*- encoding: utf-8 -*-
# stub: google-cloud-common 1.9.0 ruby lib

Gem::Specification.new do |s|
  s.name = "google-cloud-common".freeze
  s.version = "1.9.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Google LLC".freeze]
  s.date = "1980-01-02"
  s.description = "Common protocol buffer types used by Google Cloud APIs".freeze
  s.email = ["googleapis-packages@google.com".freeze]
  s.homepage = "https://github.com/googleapis/common-protos-ruby".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.1".freeze)
  s.rubygems_version = "3.6.8".freeze
  s.summary = "Common protocol buffer types used in Google Cloud APIs".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<googleapis-common-protos-types>.freeze, ["~> 1.20".freeze])
  s.add_runtime_dependency(%q<google-protobuf>.freeze, [">= 3.18".freeze, "< 5.a".freeze])
end
