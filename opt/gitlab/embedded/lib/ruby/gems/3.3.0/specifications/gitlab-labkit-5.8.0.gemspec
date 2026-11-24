# -*- encoding: utf-8 -*-
# stub: gitlab-labkit 5.8.0 ruby lib

Gem::Specification.new do |s|
  s.name = "gitlab-labkit".freeze
  s.version = "5.8.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "source_code_uri" => "https://gitlab.com/gitlab-org/ruby/gems/labkit-ruby" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Andrew Newdigate".freeze]
  s.bindir = "exe".freeze
  s.date = "1980-01-02"
  s.email = ["andrew@gitlab.com".freeze]
  s.executables = ["labkit-logging".freeze]
  s.files = ["exe/labkit-logging".freeze]
  s.homepage = "https://gitlab.com/gitlab-org/labkit-ruby".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new([">= 3.3".freeze, "< 5".freeze])
  s.rubygems_version = "4.0.20".freeze
  s.summary = "Instrumentation for GitLab".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<actionpack>.freeze, [">= 5.0.0".freeze, "< 8.2.0".freeze])
  s.add_runtime_dependency(%q<activesupport>.freeze, [">= 5.0.0".freeze, "< 8.2.0".freeze])
  s.add_runtime_dependency(%q<grpc>.freeze, [">= 1.75".freeze])
  s.add_runtime_dependency(%q<google-protobuf>.freeze, [">= 3.25".freeze, "< 5.0".freeze])
  s.add_runtime_dependency(%q<jaeger-client>.freeze, ["~> 1.1.0".freeze])
  s.add_runtime_dependency(%q<json_schemer>.freeze, [">= 2.3.0".freeze, "< 3.0".freeze])
  s.add_runtime_dependency(%q<openssl>.freeze, [">= 3.3.2".freeze, "< 5".freeze])
  s.add_runtime_dependency(%q<opentelemetry-sdk>.freeze, [">= 1.10".freeze, "< 2".freeze])
  s.add_runtime_dependency(%q<opentelemetry-instrumentation-all>.freeze, [">= 0.89".freeze, "< 1".freeze])
  s.add_runtime_dependency(%q<opentelemetry-exporter-otlp>.freeze, [">= 0.31".freeze, "< 1".freeze])
  s.add_runtime_dependency(%q<opentracing>.freeze, [">= 0.4".freeze, "< 1".freeze])
  s.add_runtime_dependency(%q<pg_query>.freeze, [">= 6.1.0".freeze, "< 7.0".freeze])
  s.add_runtime_dependency(%q<prometheus-client-mmap>.freeze, [">= 1.2".freeze, "< 2.0".freeze])
  s.add_runtime_dependency(%q<redis>.freeze, ["> 3.0.0".freeze, "< 6.0.0".freeze])
  s.add_runtime_dependency(%q<thrift>.freeze, ["< 0.25".freeze])
  s.add_development_dependency(%q<excon>.freeze, ["~> 0.78.1".freeze])
  s.add_development_dependency(%q<faraday>.freeze, ["~> 2.13".freeze])
  s.add_development_dependency(%q<gitlab-dangerfiles>.freeze, ["~> 2.11.0".freeze])
  s.add_development_dependency(%q<gitlab-styles>.freeze, ["~> 13.1".freeze])
  s.add_development_dependency(%q<grpc-tools>.freeze, [">= 1.75".freeze])
  s.add_development_dependency(%q<httparty>.freeze, ["~> 0.22.0".freeze])
  s.add_development_dependency(%q<httpclient>.freeze, ["~> 2.9.0".freeze])
  s.add_development_dependency(%q<irb>.freeze, ["~> 1.15.2".freeze])
  s.add_development_dependency(%q<pry>.freeze, ["~> 0.12".freeze])
  s.add_development_dependency(%q<pry-byebug>.freeze, ["~> 3.11".freeze])
  s.add_development_dependency(%q<rack>.freeze, ["~> 2.0".freeze])
  s.add_development_dependency(%q<railties>.freeze, [">= 5.0.0".freeze, "< 8.2.0".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 13.2".freeze])
  s.add_development_dependency(%q<rest-client>.freeze, ["~> 2.1.0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.12.0".freeze])
  s.add_development_dependency(%q<rspec-parameterized>.freeze, ["~> 1.0".freeze])
  s.add_development_dependency(%q<sidekiq>.freeze, [">= 5.2".freeze, "< 7".freeze])
  s.add_development_dependency(%q<webrick>.freeze, ["~> 1.7.0".freeze])
end
