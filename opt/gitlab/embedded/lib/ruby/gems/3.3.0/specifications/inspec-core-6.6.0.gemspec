# -*- encoding: utf-8 -*-
# stub: inspec-core 6.6.0 ruby lib

Gem::Specification.new do |s|
  s.name = "inspec-core".freeze
  s.version = "6.6.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Chef InSpec Team".freeze]
  s.date = "2023-11-14"
  s.description = "InSpec provides a framework for creating end-to-end infrastructure tests. You can use it for integration or even compliance testing. Create fully portable test profiles and use them in your workflow to ensure stability and security. Integrate InSpec in your change lifecycle for local testing, CI/CD, and deployment verification.\nThis has local support only. See the `inspec` gem for full support.\n\nPackaged distributions of Progress\u00AE Chef\u00AE products obtained from RubyGems are made available pursuant to the Progress Chef EULA at https://www.chef.io/end-user-license-agreement, unless there is an executed agreement in effect between you and Progress that covers the Progress Chef products (\"Master Agreement\"), in which case the Master Agreement shall govern.\n\nSource code obtained from the Chef GitHub repository is made available under Apache-2.0, a copy of which is included.\n\n".freeze
  s.email = ["inspec@chef.io".freeze]
  s.homepage = "https://github.com/inspec/inspec".freeze
  s.licenses = ["LicenseRef-Chef-EULA".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.7".freeze)
  s.rubygems_version = "3.3.7".freeze
  s.summary = "Infrastructure and compliance testing. Core library.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<chef-telemetry>.freeze, ["~> 1.0".freeze, ">= 1.0.8".freeze])
  s.add_runtime_dependency(%q<license-acceptance>.freeze, [">= 0.2.13".freeze, "< 3.0".freeze])
  s.add_runtime_dependency(%q<thor>.freeze, [">= 0.20".freeze, "< 1.3.0".freeze])
  s.add_runtime_dependency(%q<method_source>.freeze, [">= 0.8".freeze, "< 2.0".freeze])
  s.add_runtime_dependency(%q<rubyzip>.freeze, [">= 1.2.2".freeze, "< 3.0".freeze])
  s.add_runtime_dependency(%q<rspec>.freeze, [">= 3.9".freeze, "<= 3.12".freeze])
  s.add_runtime_dependency(%q<rspec-its>.freeze, ["~> 1.2".freeze])
  s.add_runtime_dependency(%q<pry>.freeze, ["~> 0.13".freeze])
  s.add_runtime_dependency(%q<hashie>.freeze, [">= 3.4".freeze, "< 6.0".freeze])
  s.add_runtime_dependency(%q<mixlib-log>.freeze, ["~> 3.0".freeze])
  s.add_runtime_dependency(%q<sslshake>.freeze, ["~> 1.2".freeze])
  s.add_runtime_dependency(%q<parallel>.freeze, ["~> 1.9".freeze])
  s.add_runtime_dependency(%q<faraday>.freeze, [">= 1".freeze, "< 3".freeze])
  s.add_runtime_dependency(%q<faraday-follow_redirects>.freeze, ["~> 0.3".freeze])
  s.add_runtime_dependency(%q<tty-table>.freeze, ["~> 0.10".freeze])
  s.add_runtime_dependency(%q<tty-prompt>.freeze, ["~> 0.17".freeze])
  s.add_runtime_dependency(%q<tomlrb>.freeze, [">= 1.2".freeze, "< 2.1".freeze])
  s.add_runtime_dependency(%q<addressable>.freeze, ["~> 2.4".freeze])
  s.add_runtime_dependency(%q<parslet>.freeze, [">= 1.5".freeze, "< 2.0".freeze])
  s.add_runtime_dependency(%q<semverse>.freeze, ["~> 3.0".freeze])
  s.add_runtime_dependency(%q<multipart-post>.freeze, ["~> 2.0".freeze])
  s.add_runtime_dependency(%q<train-core>.freeze, [">= 3.11.0".freeze])
  s.add_runtime_dependency(%q<chef-licensing>.freeze, [">= 0.7.5".freeze])
end
