# -*- encoding: utf-8 -*-
# stub: gitlab-glfm-markdown 0.0.48 x86_64-linux-gnu lib

Gem::Specification.new do |s|
  s.name = "gitlab-glfm-markdown".freeze
  s.version = "0.0.48".freeze
  s.platform = "x86_64-linux-gnu".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 3.3.22".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "changelog_uri" => "https://gitlab.com/gitlab-org/ruby/gems/gitlab-glfm-markdown/-/releases", "homepage_uri" => "https://gitlab.com/gitlab-org/ruby/gems/gitlab-glfm-markdown", "source_code_uri" => "https://gitlab.com/gitlab-org/ruby/gems/gitlab-glfm-markdown" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Brett Walker".freeze, "Asherah Connor".freeze]
  s.date = "2026-11-02"
  s.description = "Markdown processing for GitLab Flavored Markdown".freeze
  s.email = ["bwalker@gitlab.com".freeze, "aconnor@gitlab.com".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/ruby/gems/gitlab-glfm-markdown".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new([">= 3.1".freeze, "< 4.1.dev".freeze])
  s.rubygems_version = "3.5.23".freeze
  s.summary = "GLFM Markdown".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<rb_sys>.freeze, ["~> 0.9.128".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 13.0".freeze])
  s.add_development_dependency(%q<rake-compiler>.freeze, ["~> 1.3".freeze])
end
