# -*- encoding: utf-8 -*-
# stub: diff-lcs 1.3 ruby lib

Gem::Specification.new do |s|
  s.name = "diff-lcs".freeze
  s.version = "1.3".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Austin Ziegler".freeze]
  s.date = "2017-01-18"
  s.description = "Diff::LCS computes the difference between two Enumerable sequences using the\nMcIlroy-Hunt longest common subsequence (LCS) algorithm. It includes utilities\nto create a simple HTML diff output format and a standard diff-like tool.\n\nThis is release 1.3, providing a tentative fix to a long-standing issue related\nto incorrect detection of a patch direction. Also modernizes the gem\ninfrastructure, testing infrastructure, and provides a warning-free experience\nto Ruby 2.4 users.".freeze
  s.email = ["halostatue@gmail.com".freeze]
  s.executables = ["htmldiff".freeze, "ldiff".freeze]
  s.extra_rdoc_files = ["Code-of-Conduct.md".freeze, "Contributing.md".freeze, "History.md".freeze, "License.md".freeze, "Manifest.txt".freeze, "README.rdoc".freeze, "docs/COPYING.txt".freeze, "docs/artistic.txt".freeze]
  s.files = ["Code-of-Conduct.md".freeze, "Contributing.md".freeze, "History.md".freeze, "License.md".freeze, "Manifest.txt".freeze, "README.rdoc".freeze, "bin/htmldiff".freeze, "bin/ldiff".freeze, "docs/COPYING.txt".freeze, "docs/artistic.txt".freeze]
  s.homepage = "https://github.com/halostatue/diff-lcs".freeze
  s.licenses = ["MIT".freeze, "Artistic-2.0".freeze, "GPL-2.0+".freeze]
  s.rdoc_options = ["--main".freeze, "README.rdoc".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 1.8".freeze)
  s.rubygems_version = "2.5.1".freeze
  s.summary = "Diff::LCS computes the difference between two Enumerable sequences using the McIlroy-Hunt longest common subsequence (LCS) algorithm".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<hoe-doofus>.freeze, ["~> 1.0".freeze])
  s.add_development_dependency(%q<hoe-gemspec2>.freeze, ["~> 1.1".freeze])
  s.add_development_dependency(%q<hoe-git>.freeze, ["~> 1.6".freeze])
  s.add_development_dependency(%q<hoe-rubygems>.freeze, ["~> 1.0".freeze])
  s.add_development_dependency(%q<hoe-travis>.freeze, ["~> 1.2".freeze])
  s.add_development_dependency(%q<rspec>.freeze, [">= 2.0".freeze, "< 4".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 10.0".freeze, "< 12".freeze])
  s.add_development_dependency(%q<rdoc>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<hoe>.freeze, ["~> 3.16".freeze])
end
