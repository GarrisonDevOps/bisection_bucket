# -*- encoding: utf-8 -*-
# stub: winrm-fs 1.3.5 ruby lib

Gem::Specification.new do |s|
  s.name = "winrm-fs".freeze
  s.version = "1.3.5".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Shawn Neal".freeze, "Matt Wrock".freeze]
  s.date = "2020-09-10"
  s.description = "    Ruby library for file system operations via Windows Remote Management\n".freeze
  s.email = ["sneal@sneal.net".freeze, "matt@mattwrock.com".freeze]
  s.executables = ["rwinrmcp".freeze]
  s.extra_rdoc_files = ["README.md".freeze, "LICENSE".freeze]
  s.files = ["LICENSE".freeze, "README.md".freeze, "bin/rwinrmcp".freeze]
  s.homepage = "http://github.com/WinRb/winrm-fs".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.rdoc_options = ["-x".freeze, "test/".freeze, "-x".freeze, "examples/".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.4.0".freeze)
  s.rubygems_version = "3.1.2".freeze
  s.summary = "WinRM File System".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<erubi>.freeze, ["~> 1.8".freeze])
  s.add_runtime_dependency(%q<logging>.freeze, [">= 1.6.1".freeze, "< 3.0".freeze])
  s.add_runtime_dependency(%q<rubyzip>.freeze, ["~> 2.0".freeze])
  s.add_runtime_dependency(%q<winrm>.freeze, ["~> 2.0".freeze])
  s.add_development_dependency(%q<pry>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 10.3".freeze, "< 13".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.0".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, ["~> 0.68.0".freeze])
end
