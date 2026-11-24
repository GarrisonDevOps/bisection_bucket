# -*- encoding: utf-8 -*-
# stub: chef-bin 18.3.0 ruby lib

Gem::Specification.new do |s|
  s.name = "chef-bin".freeze
  s.version = "18.3.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Adam Jacob".freeze]
  s.date = "2023-09-21"
  s.email = ["adam@chef.io".freeze]
  s.executables = ["cinc-apply".freeze, "cinc-client".freeze, "cinc-resource-inspector".freeze, "cinc-service-manager".freeze, "cinc-shell".freeze, "cinc-solo".freeze, "cinc-windows-service".freeze, "cinc-wrapper".freeze, "chef-apply".freeze, "chef-client".freeze, "chef-shell".freeze, "chef-solo".freeze, "inspec".freeze]
  s.files = ["bin/chef-apply".freeze, "bin/chef-client".freeze, "bin/chef-shell".freeze, "bin/chef-solo".freeze, "bin/cinc-apply".freeze, "bin/cinc-client".freeze, "bin/cinc-resource-inspector".freeze, "bin/cinc-service-manager".freeze, "bin/cinc-shell".freeze, "bin/cinc-solo".freeze, "bin/cinc-windows-service".freeze, "bin/cinc-wrapper".freeze, "bin/inspec".freeze]
  s.homepage = "https://github.com/chef/chef".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.rubygems_version = "3.3.7".freeze
  s.summary = "Chef-branded binstubs for chef-client".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<chef>.freeze, ["= 18.3.0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0".freeze])
end
