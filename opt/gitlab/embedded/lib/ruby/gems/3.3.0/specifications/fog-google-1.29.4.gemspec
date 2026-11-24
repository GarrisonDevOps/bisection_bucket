# -*- encoding: utf-8 -*-
# stub: fog-google 1.29.4 ruby lib

Gem::Specification.new do |s|
  s.name = "fog-google".freeze
  s.version = "1.29.4".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Nat Welch".freeze, "Artem Yakimenko".freeze]
  s.date = "1980-01-02"
  s.description = "This library can be used as a module for `fog` or as standalone provider to use the Google Cloud in applications.".freeze
  s.email = ["nat@natwelch.com".freeze, "temikus@google.com".freeze]
  s.homepage = "https://github.com/fog/fog-google".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.0".freeze)
  s.rubygems_version = "3.7.2".freeze
  s.summary = "Module for the 'fog' gem to support Google.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<fog-core>.freeze, ["~> 2.5".freeze])
  s.add_runtime_dependency(%q<fog-json>.freeze, ["~> 1.2".freeze])
  s.add_runtime_dependency(%q<fog-xml>.freeze, ["~> 0.1.0".freeze])
  s.add_runtime_dependency(%q<google-apis-storage_v1>.freeze, [">= 0.19".freeze, "< 1".freeze])
  s.add_runtime_dependency(%q<google-apis-iamcredentials_v1>.freeze, ["~> 0.15".freeze])
  s.add_runtime_dependency(%q<google-apis-compute_v1>.freeze, ["~> 0.53".freeze])
  s.add_runtime_dependency(%q<google-apis-monitoring_v3>.freeze, ["~> 0.37".freeze])
  s.add_runtime_dependency(%q<google-apis-dns_v1>.freeze, ["~> 0.28".freeze])
  s.add_runtime_dependency(%q<google-apis-pubsub_v1>.freeze, ["~> 0.30".freeze])
  s.add_runtime_dependency(%q<google-apis-sqladmin_v1beta4>.freeze, ["~> 0.38".freeze])
  s.add_runtime_dependency(%q<google-cloud-env>.freeze, [">= 1.2".freeze, "< 3.0".freeze])
  s.add_runtime_dependency(%q<addressable>.freeze, [">= 2.7.0".freeze])
  s.add_development_dependency(%q<pry>.freeze, ["= 0.16.0".freeze])
  s.add_development_dependency(%q<retriable>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<minitest>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<minitest-mock>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<minitest-reporters>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<shindo>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<vcr>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<webmock>.freeze, [">= 0".freeze])
end
