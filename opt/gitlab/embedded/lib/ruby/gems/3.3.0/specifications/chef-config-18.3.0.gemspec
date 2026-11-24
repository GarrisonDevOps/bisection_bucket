# -*- encoding: utf-8 -*-
# stub: chef-config 18.3.0 ruby lib

Gem::Specification.new do |s|
  s.name = "chef-config".freeze
  s.version = "18.3.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://github.com/chef/chef/issues", "changelog_uri" => "https://github.com/chef/chef/blob/main/CHANGELOG.md", "documentation_uri" => "https://github.com/chef/chef/tree/main/chef-config/README.md", "homepage_uri" => "https://github.com/chef/chef/tree/main/chef-config", "source_code_uri" => "https://github.com/chef/chef/tree/main/chef-config" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Adam Jacob".freeze]
  s.date = "2023-09-21"
  s.email = ["adam@chef.io".freeze]
  s.homepage = "https://github.com/chef/chef".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.6".freeze)
  s.rubygems_version = "3.3.7".freeze
  s.summary = "Chef Infra's default configuration and config loading library".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<chef-utils>.freeze, ["= 18.3.0".freeze])
  s.add_runtime_dependency(%q<mixlib-shellout>.freeze, [">= 2.0".freeze, "< 4.0".freeze])
  s.add_runtime_dependency(%q<mixlib-config>.freeze, [">= 2.2.12".freeze, "< 4.0".freeze])
  s.add_runtime_dependency(%q<fuzzyurl>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<addressable>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<tomlrb>.freeze, ["~> 1.2".freeze])
end
