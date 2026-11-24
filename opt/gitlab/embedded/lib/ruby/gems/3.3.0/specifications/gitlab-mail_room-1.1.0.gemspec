# -*- encoding: utf-8 -*-
# stub: gitlab-mail_room 1.1.0 ruby lib

Gem::Specification.new do |s|
  s.name = "gitlab-mail_room".freeze
  s.version = "1.1.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Tony Pitale".freeze]
  s.date = "2026-06-18"
  s.description = "mail_room will proxy email (gmail) from IMAP to a delivery method".freeze
  s.email = ["tpitale@gmail.com".freeze]
  s.executables = ["mail_room".freeze]
  s.files = ["bin/mail_room".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/ruby/gems/gitlab-mail_room".freeze
  s.required_ruby_version = Gem::Requirement.new(">= 3.1".freeze)
  s.rubygems_version = "3.6.2".freeze
  s.summary = "mail_room will proxy email (gmail) from IMAP to a callback URL, logger, or letter_opener".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<net-imap>.freeze, [">= 0.5".freeze, "< 0.7".freeze])
  s.add_runtime_dependency(%q<oauth2>.freeze, [">= 2.0.9".freeze, "< 3".freeze])
  s.add_runtime_dependency(%q<jwt>.freeze, [">= 2.0".freeze, "< 4".freeze])
  s.add_runtime_dependency(%q<redis>.freeze, [">= 5".freeze, "< 6".freeze])
  s.add_runtime_dependency(%q<redis-namespace>.freeze, [">= 1.8.2".freeze, "< 2".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.9".freeze])
  s.add_development_dependency(%q<rubocop>.freeze, ["~> 1.11".freeze])
  s.add_development_dependency(%q<mocha>.freeze, ["~> 2.0".freeze])
  s.add_development_dependency(%q<simplecov>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<webrick>.freeze, ["~> 1.6".freeze])
  s.add_development_dependency(%q<faraday>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<mail>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<letter_opener>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<pg>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<charlock_holmes>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<webmock>.freeze, [">= 0".freeze])
end
