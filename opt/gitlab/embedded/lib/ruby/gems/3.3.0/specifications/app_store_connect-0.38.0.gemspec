# -*- encoding: utf-8 -*-
# stub: app_store_connect 0.38.0 ruby lib

Gem::Specification.new do |s|
  s.name = "app_store_connect".freeze
  s.version = "0.38.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Kyle Decot".freeze]
  s.date = "2023-05-02"
  s.email = ["kyle.decot@icloud.com".freeze]
  s.homepage = "https://github.com/kyledecot/app_store_connect".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.7.0".freeze)
  s.rubygems_version = "3.3.26".freeze
  s.summary = "A Ruby interface to the App Store Connect API".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<activesupport>.freeze, [">= 6.0.0".freeze])
  s.add_runtime_dependency(%q<jwt>.freeze, [">= 1.4".freeze])
  s.add_runtime_dependency(%q<zeitwerk>.freeze, [">= 2.6.7".freeze])
  s.add_development_dependency(%q<bundler>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<erb>.freeze, ["~> 4.0.2".freeze])
  s.add_development_dependency(%q<factory_bot>.freeze, ["~> 6.2.1".freeze])
  s.add_development_dependency(%q<github_changelog_generator>.freeze, ["= 1.16.4".freeze])
  s.add_development_dependency(%q<guard-rspec>.freeze, ["~> 4.7.3".freeze])
  s.add_development_dependency(%q<pry>.freeze, ["~> 0.14.1".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 13.0.6".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.12.0".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, ["~> 1.50.1".freeze])
  s.add_development_dependency(%q<rubyzip>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<semantic>.freeze, ["~> 1.6.1".freeze])
  s.add_development_dependency(%q<simplecov>.freeze, ["~> 0.22.0".freeze])
  s.add_development_dependency(%q<timecop>.freeze, ["~> 0.9.5".freeze])
  s.add_development_dependency(%q<webmock>.freeze, ["~> 3.18.1".freeze])
end
