# -*- encoding: utf-8 -*-
# stub: gitlab-fog-azure-rm 2.5.2 ruby lib

Gem::Specification.new do |s|
  s.name = "gitlab-fog-azure-rm".freeze
  s.version = "2.5.2".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Shaffan Chaudhry".freeze, "Samawia Moin".freeze, "Adnan Khalil".freeze, "Zeeshan Arshad".freeze, "Haider Ali".freeze, "Waqar Haider".freeze, "Bilal Naeem".freeze, "Muhammad Asad".freeze, "Azeem Sajid".freeze, "Maham Nazir".freeze, "Abbas Sheikh".freeze]
  s.date = "2026-09-23"
  s.description = "This is a stripped-down fork of fog-azure-rm that enables Azure Blob Storage to be used with CarrierWave and Fog.".freeze
  s.extra_rdoc_files = ["README.md".freeze]
  s.files = ["README.md".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/gitlab-fog-azure-rm".freeze
  s.licenses = ["MIT".freeze]
  s.post_install_message = "Thanks for installing!".freeze
  s.rdoc_options = ["--charset=UTF-8".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.2.0".freeze)
  s.rubygems_version = "3.5.22".freeze
  s.summary = "Module for the 'fog' gem to support Azure Blob Storage with CarrierWave and Fog.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<codeclimate-test-reporter>.freeze, ["~> 1.0.0".freeze])
  s.add_development_dependency(%q<minitest>.freeze, ["~> 5.27".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 13.0".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, ["~> 1.86.0".freeze])
  s.add_development_dependency(%q<simplecov>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<timecop>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<webmock>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<webrick>.freeze, ["~> 1.8".freeze])
  s.add_runtime_dependency(%q<base64>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<faraday>.freeze, ["~> 2.0".freeze])
  s.add_runtime_dependency(%q<faraday-follow_redirects>.freeze, ["~> 0.5.0".freeze])
  s.add_runtime_dependency(%q<faraday-net_http_persistent>.freeze, ["~> 2.0".freeze])
  s.add_runtime_dependency(%q<fog-core>.freeze, ["~> 2.1".freeze])
  s.add_runtime_dependency(%q<fog-json>.freeze, ["~> 1.2".freeze])
  s.add_runtime_dependency(%q<mime-types>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<net-http-persistent>.freeze, ["~> 4.0".freeze])
  s.add_runtime_dependency(%q<nokogiri>.freeze, ["~> 1".freeze, ">= 1.10.8".freeze])
end
