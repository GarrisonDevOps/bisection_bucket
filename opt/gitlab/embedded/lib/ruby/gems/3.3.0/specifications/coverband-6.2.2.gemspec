# -*- encoding: utf-8 -*-
# stub: coverband 6.2.2 ruby lib

Gem::Specification.new do |s|
  s.name = "coverband".freeze
  s.version = "6.2.2".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://github.com/danmayer/coverband/issues", "changelog_uri" => "https://github.com/danmayer/coverband/blob/main/changes.md", "documentation_uri" => "https://github.com/danmayer/coverband", "homepage_uri" => "https://github.com/danmayer/coverband", "source_code_uri" => "https://github.com/danmayer/coverband" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Dan Mayer".freeze, "Karl Baum".freeze]
  s.date = "1980-01-02"
  s.description = "Rack middleware to measure production code usage (LOC runtime usage)".freeze
  s.email = ["dan@mayerdan.com".freeze]
  s.executables = ["coverband-mcp".freeze]
  s.files = ["bin/coverband-mcp".freeze]
  s.homepage = "https://github.com/danmayer/coverband".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.1".freeze)
  s.rubygems_version = "3.6.9".freeze
  s.summary = "Rack middleware to measure production code usage (LOC runtime usage)".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<benchmark-ips>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<benchmark>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<capybara>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<m>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<memory_profiler>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<spy>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<minitest>.freeze, ["~> 5.0".freeze])
  s.add_development_dependency(%q<minitest-fork_executor>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<minitest-stub-const>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<mocha>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rack>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rack-test>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<resque>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<standard>.freeze, [">= 1.35.1".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<coveralls>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<webmock>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<dalli>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<mcp>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<redis>.freeze, [">= 3.0".freeze])
  s.add_runtime_dependency(%q<base64>.freeze, [">= 0".freeze])
end
