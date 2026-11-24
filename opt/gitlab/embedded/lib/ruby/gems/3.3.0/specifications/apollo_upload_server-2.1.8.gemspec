# -*- encoding: utf-8 -*-
# stub: apollo_upload_server 2.1.8 ruby lib

Gem::Specification.new do |s|
  s.name = "apollo_upload_server".freeze
  s.version = "2.1.8".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["JetRuby".freeze]
  s.date = "1980-01-02"
  s.description = "apollo-upload-server implementation for Ruby on Rails as middleware.".freeze
  s.email = ["engineering@jetruby.com".freeze]
  s.homepage = "https://github.com/jetruby/apollo_upload_server-ruby".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "3.6.9".freeze
  s.summary = "Middleware which allows you to upload files using graphql and multipart/form-data.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<actionpack>.freeze, [">= 6.1.6".freeze])
  s.add_runtime_dependency(%q<graphql>.freeze, [">= 1.8".freeze])
  s.add_development_dependency(%q<bundler>.freeze, ["~> 2.1".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 13.0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.11".freeze])
end
