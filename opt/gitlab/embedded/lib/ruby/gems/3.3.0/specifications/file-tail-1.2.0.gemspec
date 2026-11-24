# -*- encoding: utf-8 -*-
# stub: file-tail 1.2.0 ruby lib

Gem::Specification.new do |s|
  s.name = "file-tail".freeze
  s.version = "1.2.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Florian Frank".freeze]
  s.date = "2017-04-13"
  s.description = "Library to tail files in Ruby".freeze
  s.email = "flori@ping.de".freeze
  s.extra_rdoc_files = ["README.md".freeze, "lib/file-tail.rb".freeze, "lib/file/tail.rb".freeze, "lib/file/tail/group.rb".freeze, "lib/file/tail/line_extension.rb".freeze, "lib/file/tail/logfile.rb".freeze, "lib/file/tail/tailer.rb".freeze, "lib/file/tail/version.rb".freeze]
  s.files = ["README.md".freeze, "lib/file-tail.rb".freeze, "lib/file/tail.rb".freeze, "lib/file/tail/group.rb".freeze, "lib/file/tail/line_extension.rb".freeze, "lib/file/tail/logfile.rb".freeze, "lib/file/tail/tailer.rb".freeze, "lib/file/tail/version.rb".freeze]
  s.homepage = "http://github.com/flori/file-tail".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.rdoc_options = ["--title".freeze, "File-tail - File::Tail for Ruby".freeze, "--main".freeze, "README.md".freeze]
  s.rubygems_version = "2.6.11".freeze
  s.summary = "File::Tail for Ruby".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<gem_hadar>.freeze, ["~> 1.9.1".freeze])
  s.add_development_dependency(%q<test-unit>.freeze, ["~> 2.4.0".freeze])
  s.add_runtime_dependency(%q<tins>.freeze, ["~> 1.0".freeze])
end
