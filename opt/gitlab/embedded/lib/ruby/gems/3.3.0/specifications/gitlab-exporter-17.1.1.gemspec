# -*- encoding: utf-8 -*-
# stub: gitlab-exporter 17.1.1 ruby lib

Gem::Specification.new do |s|
  s.name = "gitlab-exporter".freeze
  s.version = "17.1.1".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Pablo Carranza".freeze]
  s.date = "2016-07-27"
  s.description = "GitLab metrics exporter to use with prometheus".freeze
  s.email = "pablo@gitlab.com".freeze
  s.executables = ["gitlab-exporter".freeze]
  s.files = ["bin/gitlab-exporter".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/ruby/gems/gitlab-exporter".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.1".freeze)
  s.rubygems_version = "3.5.22".freeze
  s.summary = "GitLab metrics exporter".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<base64>.freeze, ["= 0.3.0".freeze])
  s.add_runtime_dependency(%q<connection_pool>.freeze, ["= 2.5.5".freeze])
  s.add_runtime_dependency(%q<deep_merge>.freeze, ["~> 1.2.2".freeze])
  s.add_runtime_dependency(%q<faraday>.freeze, ["= 2.14.4".freeze])
  s.add_runtime_dependency(%q<pg>.freeze, ["= 1.6.3".freeze])
  s.add_runtime_dependency(%q<quantile>.freeze, ["= 0.2.1".freeze])
  s.add_runtime_dependency(%q<redis>.freeze, ["= 4.8.1".freeze])
  s.add_runtime_dependency(%q<redis-namespace>.freeze, ["= 1.11.0".freeze])
  s.add_runtime_dependency(%q<sidekiq>.freeze, ["= 6.5.12".freeze])
  s.add_runtime_dependency(%q<webrick>.freeze, ["~> 1.9".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.12.0".freeze])
  s.add_development_dependency(%q<rspec-expectations>.freeze, ["~> 3.12.0".freeze])
end
