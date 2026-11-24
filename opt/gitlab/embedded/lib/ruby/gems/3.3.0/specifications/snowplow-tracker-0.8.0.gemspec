# -*- encoding: utf-8 -*-
# stub: snowplow-tracker 0.8.0 ruby lib

Gem::Specification.new do |s|
  s.name = "snowplow-tracker".freeze
  s.version = "0.8.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Snowplow Analytics Ltd".freeze]
  s.date = "2021-10-29"
  s.description = "With this tracker you can collect event data from your Ruby applications, Ruby on Rails web applications and Ruby gems.".freeze
  s.email = "support@snowplowanalytics.com".freeze
  s.homepage = "http://github.com/snowplow/snowplow-ruby-tracker".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.1".freeze)
  s.rubygems_version = "3.0.3.1".freeze
  s.summary = "Ruby Analytics for Snowplow".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.10".freeze])
  s.add_development_dependency(%q<webmock>.freeze, ["~> 3.14".freeze])
end
