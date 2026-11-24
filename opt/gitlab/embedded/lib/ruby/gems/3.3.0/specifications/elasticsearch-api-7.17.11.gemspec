# -*- encoding: utf-8 -*-
# stub: elasticsearch-api 7.17.11 ruby lib

Gem::Specification.new do |s|
  s.name = "elasticsearch-api".freeze
  s.version = "7.17.11".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://github.com/elastic/elasticsearch-ruby/issues", "changelog_uri" => "https://github.com/elastic/elasticsearch-ruby/blob/7.16/CHANGELOG.md", "homepage_uri" => "https://www.elastic.co/guide/en/elasticsearch/client/ruby-api/7.16/index.html", "source_code_uri" => "https://github.com/elastic/elasticsearch-ruby/tree/7.16/elasticsearch-api" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Karel Minarik".freeze]
  s.date = "2024-06-03"
  s.description = "Ruby API for Elasticsearch. See the `elasticsearch` gem for full integration.\n".freeze
  s.email = ["karel.minarik@elasticsearch.org".freeze]
  s.extra_rdoc_files = ["README.md".freeze, "LICENSE".freeze]
  s.files = ["LICENSE".freeze, "README.md".freeze]
  s.homepage = "https://www.elastic.co/guide/en/elasticsearch/client/ruby-api/7.16/index.html".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.rdoc_options = ["--charset=UTF-8".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.4".freeze)
  s.rubygems_version = "3.5.9".freeze
  s.summary = "Ruby API for Elasticsearch.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<multi_json>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<ansi>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<bundler>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<elasticsearch>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<elasticsearch-transport>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<elasticsearch-xpack>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<minitest>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<minitest-reporters>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<mocha>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<pry>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 13".freeze])
  s.add_development_dependency(%q<shoulda-context>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<yard>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<jsonify>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<hashie>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<activesupport>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<jbuilder>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<cane>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<escape_utils>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<require-prof>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<simplecov>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<test-unit>.freeze, ["~> 2".freeze])
  s.add_development_dependency(%q<ruby-prof>.freeze, [">= 0".freeze])
end
