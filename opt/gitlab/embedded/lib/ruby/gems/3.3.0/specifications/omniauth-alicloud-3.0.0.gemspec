# -*- encoding: utf-8 -*-
# stub: omniauth-alicloud 3.0.0 ruby lib

Gem::Specification.new do |s|
  s.name = "omniauth-alicloud".freeze
  s.version = "3.0.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "homepage_uri" => "https://gitlab.com/gitlab-jh/jh-team/omniauth-alicloud", "source_code_uri" => "https://gitlab.com/gitlab-jh/jh-team/omniauth-alicloud" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["JiHu(GitLab)".freeze]
  s.bindir = "exe".freeze
  s.date = "2023-09-15"
  s.description = "Wrapper the AliCloud Oauth2 API".freeze
  s.email = ["dev@jihulab.com".freeze]
  s.homepage = "https://gitlab.com/gitlab-jh/jh-team/omniauth-alicloud".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "3.2.22".freeze
  s.summary = "Omniauth strategy for AliCloud".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<omniauth-oauth2>.freeze, ["~> 1.8".freeze])
end
