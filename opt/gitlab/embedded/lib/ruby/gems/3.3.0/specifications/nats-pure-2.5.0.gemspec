# -*- encoding: utf-8 -*-
# stub: nats-pure 2.5.0 ruby lib

Gem::Specification.new do |s|
  s.name = "nats-pure".freeze
  s.version = "2.5.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://github.com/nats-io/nats-pure.rb/issues", "changelog_uri" => "https://github.com/nats-io/nats-pure.rb/blob/main/CHANGELOG.md", "documentation_uri" => "https://github.com/nats-io/nats-pure.rb", "homepage_uri" => "https://github.com/nats-io/nats-pure.rb", "source_code_uri" => "https://github.com/nats-io/nats-pure.rb" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Waldemar Quevedo".freeze]
  s.date = "2025-02-21"
  s.description = "NATS is an open-source, high-performance, lightweight cloud messaging system.".freeze
  s.email = ["wally@synadia.com".freeze]
  s.homepage = "https://nats.io".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.0".freeze)
  s.rubygems_version = "3.5.11".freeze
  s.summary = "NATS is an open-source, high-performance, lightweight cloud messaging system.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<concurrent-ruby>.freeze, ["~> 1.0".freeze])
  s.add_runtime_dependency(%q<uri>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<securerandom>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<json>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<base64>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<nkeys>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<websocket>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<bundler>.freeze, [">= 1".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 13.0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, [">= 3.5".freeze])
  s.add_development_dependency(%q<timecop>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<resolv-replace>.freeze, [">= 0".freeze])
end
