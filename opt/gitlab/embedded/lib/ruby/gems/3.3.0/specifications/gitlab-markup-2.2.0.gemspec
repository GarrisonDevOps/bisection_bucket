# -*- encoding: utf-8 -*-
# stub: gitlab-markup 2.2.0 ruby lib

Gem::Specification.new do |s|
  s.name = "gitlab-markup".freeze
  s.version = "2.2.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://gitlab.com/gitlab-org/gitlab-markup/issues", "changelog_uri" => "https://gitlab.com/gitlab-org/gitlab-markup/blob/master/HISTORY.md", "source_code_uri" => "https://gitlab.com/gitlab-org/gitlab-markup" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Chris Wanstrath".freeze, "GitLab Engineering Team".freeze]
  s.date = "1980-01-02"
  s.description = "This gem is used by GitLab to render any non Markdown markup".freeze
  s.email = "engineering@gitlab.com".freeze
  s.executables = ["gitlab-markup".freeze]
  s.files = ["bin/gitlab-markup".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/gitlab-markup".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.2".freeze)
  s.rubygems_version = "3.7.2".freeze
  s.summary = "Fork from github-markup GitLab uses to render non markdown content".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<activesupport>.freeze, ["~> 4.0".freeze])
  s.add_development_dependency(%q<html-pipeline>.freeze, ["~> 1.0".freeze])
  s.add_development_dependency(%q<logger>.freeze, ["~> 1.6.6".freeze])
  s.add_development_dependency(%q<minitest>.freeze, ["~> 5.4.3".freeze])
  s.add_development_dependency(%q<mutex_m>.freeze, ["~> 0.3.0".freeze])
  s.add_development_dependency(%q<nokogiri>.freeze, ["~> 1.13.8".freeze])
  s.add_development_dependency(%q<nokogiri-diff>.freeze, ["~> 0.2.0".freeze])
  s.add_development_dependency(%q<rdoc>.freeze, [">= 6.13".freeze, "< 9".freeze])
  s.add_development_dependency(%q<sanitize>.freeze, ["~> 6.0.0".freeze])
  s.add_runtime_dependency(%q<RedCloth>.freeze, ["~> 4.3".freeze])
  s.add_runtime_dependency(%q<rdoc>.freeze, [">= 6.13".freeze, "< 9".freeze])
  s.add_runtime_dependency(%q<org-ruby>.freeze, ["~> 0.9".freeze])
  s.add_runtime_dependency(%q<creole>.freeze, ["~> 0.5.0".freeze])
  s.add_runtime_dependency(%q<wikicloth>.freeze, ["= 0.8.1".freeze])
end
