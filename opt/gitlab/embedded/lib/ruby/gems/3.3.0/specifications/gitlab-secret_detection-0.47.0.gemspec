# -*- encoding: utf-8 -*-
# stub: gitlab-secret_detection 0.47.0 ruby lib

Gem::Specification.new do |s|
  s.name = "gitlab-secret_detection".freeze
  s.version = "0.47.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "changelog_uri" => "https://gitlab.com/gitlab-org/security-products/secret-detection/secret-detection-service/-/blob/main/CHANGELOG.md", "homepage_uri" => "https://gitlab.com/gitlab-org/security-products/secret-detection/secret-detection-service", "rubygems_mfa_required" => "true", "source_code_uri" => "https://gitlab.com/gitlab-org/security-products/secret-detection/secret-detection-service" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["group::secret detection".freeze, "Stan Hu".freeze, "gitlab_rubygems".freeze]
  s.date = "1980-01-02"
  s.description = "GitLab Secret Detection gem accepts text-based payloads, matches them against predefined secret\n    detection rules (based on the ruleset used by GitLab Secrets analyzer), and returns the scan results. The gem also\n    supports customization of the scan behaviour.".freeze
  s.email = ["eng-dev-secure-secret-detection@gitlab.com".freeze, "stan@gitlab.com".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/security-products/secret-detection/secret-detection-service".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.2".freeze)
  s.rubygems_version = "3.6.9".freeze
  s.summary = "GitLab Secret Detection gem scans for the secret leaks in the given text-based payloads.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<grpc>.freeze, [">= 1.63.0".freeze, "< 2".freeze])
  s.add_runtime_dependency(%q<grpc_reflection>.freeze, ["~> 0.1".freeze])
  s.add_runtime_dependency(%q<parallel>.freeze, ["~> 1".freeze])
  s.add_runtime_dependency(%q<re2>.freeze, ["~> 2.7".freeze])
  s.add_runtime_dependency(%q<sentry-ruby>.freeze, ["~> 5.22".freeze])
  s.add_runtime_dependency(%q<stackprof>.freeze, ["~> 0.2.27".freeze])
  s.add_runtime_dependency(%q<toml-rb>.freeze, ["~> 4.1".freeze])
  s.add_development_dependency(%q<benchmark-malloc>.freeze, ["~> 0.2".freeze])
  s.add_development_dependency(%q<gitlab-styles>.freeze, ["~> 13.1.0".freeze])
  s.add_development_dependency(%q<grpc-tools>.freeze, ["~> 1.63".freeze])
  s.add_development_dependency(%q<lefthook>.freeze, ["~> 1.7".freeze])
  s.add_development_dependency(%q<pry-byebug>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.13".freeze])
  s.add_development_dependency(%q<rspec-benchmark>.freeze, ["~> 0.6.0".freeze])
  s.add_development_dependency(%q<rspec-parameterized>.freeze, ["~> 1.0".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rubocop-rspec>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<simplecov>.freeze, [">= 0".freeze])
end
