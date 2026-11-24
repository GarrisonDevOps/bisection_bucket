# -*- encoding: utf-8 -*-
# stub: opentelemetry-helpers-sql-processor 0.5.0 ruby lib

Gem::Specification.new do |s|
  s.name = "opentelemetry-helpers-sql-processor".freeze
  s.version = "0.5.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://github.com/open-telemetry/opentelemetry-ruby-contrib/issues", "changelog_uri" => "https://rubydoc.info/gems/opentelemetry-helpers-sql-processor/0.5.0/file/CHANGELOG.md", "documentation_uri" => "https://rubydoc.info/gems/opentelemetry-helpers-sql-processor/0.5.0", "source_code_uri" => "https://github.com/open-telemetry/opentelemetry-ruby-contrib/tree/opentelemetry-helpers-sql-processor/v0.5.0/helpers/sql-processor" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["OpenTelemetry Authors".freeze]
  s.date = "1980-01-02"
  s.description = "SQL Processing Instrumentation Helpers for the OpenTelemetry framework".freeze
  s.email = ["cncf-opentelemetry-contributors@lists.cncf.io".freeze]
  s.homepage = "https://github.com/open-telemetry/opentelemetry-ruby-contrib".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.post_install_message = "".freeze
  s.required_ruby_version = Gem::Requirement.new(">= 3.3".freeze)
  s.rubygems_version = "4.0.6".freeze
  s.summary = "SQL Processing Instrumentation Helpers for the OpenTelemetry framework".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<opentelemetry-api>.freeze, ["~> 1.0".freeze])
  s.add_runtime_dependency(%q<opentelemetry-common>.freeze, ["~> 0.21".freeze])
end
