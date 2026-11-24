# -*- encoding: utf-8 -*-
# stub: jira-ruby 3.2.2 ruby lib

Gem::Specification.new do |s|
  s.name = "jira-ruby".freeze
  s.version = "3.2.2".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "rubygems_mfa_required" => "true", "source_code_uri" => "https://github.com/sumoheavy/jira-ruby" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["SUMO Heavy Industries".freeze, "test IO".freeze]
  s.date = "2026-08-19"
  s.description = "API for JIRA".freeze
  s.homepage = "http://www.sumoheavy.com".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.1.0".freeze)
  s.rubygems_version = "3.6.2".freeze
  s.summary = "Ruby Gem for use with the Atlassian JIRA REST API".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<activesupport>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<cgi>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<jwt>.freeze, [">= 2.1".freeze])
  s.add_runtime_dependency(%q<multipart-post>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<oauth>.freeze, ["~> 1.0".freeze])
end
