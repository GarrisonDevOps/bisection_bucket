# -*- encoding: utf-8 -*-
# stub: licensee 10.0.0 ruby lib

Gem::Specification.new do |s|
  s.name = "licensee".freeze
  s.version = "10.0.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "rubygems_mfa_required" => "true" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Ben Balter".freeze]
  s.date = "2026-05-05"
  s.description = "    Licensee automates the process of reading LICENSE files and\n    compares their contents to known licenses using a fancy maths.\n".freeze
  s.email = "ben.balter@github.com".freeze
  s.executables = ["licensee".freeze]
  s.files = ["bin/licensee".freeze]
  s.homepage = "https://github.com/licensee/licensee".freeze
  s.licenses = ["MIT".freeze]
  s.post_install_message = "NOTE: The rugged gem is no longer a required dependency of licensee.\nIf you scan bare Git repositories or Git repos without a working tree,\nadd rugged to your Gemfile or run: gem install rugged\n".freeze
  s.required_ruby_version = Gem::Requirement.new(">= 3.2".freeze)
  s.rubygems_version = "3.6.2".freeze
  s.summary = "A Ruby Gem to detect open source project licenses".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<dotenv>.freeze, [">= 2".freeze, "< 4".freeze])
  s.add_runtime_dependency(%q<octokit>.freeze, [">= 4.20".freeze, "< 11.0".freeze])
  s.add_runtime_dependency(%q<reverse_markdown>.freeze, [">= 1".freeze, "< 4".freeze])
  s.add_runtime_dependency(%q<thor>.freeze, [">= 0.19".freeze, "< 2.0".freeze])
  s.add_development_dependency(%q<gem-release>.freeze, ["~> 2.0".freeze])
  s.add_development_dependency(%q<mustache>.freeze, [">= 0.9".freeze, "< 2.0".freeze])
  s.add_development_dependency(%q<pry>.freeze, ["~> 0.9".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.5".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, ["~> 1.0".freeze])
  s.add_development_dependency(%q<rubocop-performance>.freeze, ["~> 1.5".freeze])
  s.add_development_dependency(%q<rubocop-rspec>.freeze, ["~> 3.0".freeze])
  s.add_development_dependency(%q<rugged>.freeze, [">= 0.24".freeze, "< 2.0".freeze])
  s.add_development_dependency(%q<simplecov>.freeze, ["~> 0.16".freeze])
  s.add_development_dependency(%q<webmock>.freeze, ["~> 3.1".freeze])
end
