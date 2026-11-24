# -*- encoding: utf-8 -*-
# stub: remote_syslog-gitlab 0.0.2 ruby lib

Gem::Specification.new do |s|
  s.name = "remote_syslog-gitlab".freeze
  s.version = "0.0.2".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Troy Davis".freeze, "Eric Lindvall".freeze]
  s.date = "2025-03-28"
  s.description = "Lightweight daemon to tail one or more log files and transmit UDP syslog messages to a remote syslog host (centralized log aggregation). Generates UDP packets itself instead of depending on a system syslog daemon, so it doesn't affect system-wide logging configuration.".freeze
  s.email = ["troy@sevenscale.com".freeze, "eric@sevenscale.com".freeze]
  s.executables = ["remote_syslog".freeze]
  s.extra_rdoc_files = ["README.md".freeze, "LICENSE".freeze]
  s.files = ["LICENSE".freeze, "README.md".freeze, "bin/remote_syslog".freeze]
  s.homepage = "http://github.com/papertrail/remote_syslog".freeze
  s.rdoc_options = ["--charset=UTF-8".freeze]
  s.rubygems_version = "3.5.16".freeze
  s.summary = "Monitor plain text log file(s) for new entries and send to remote syslog collector".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 2

  s.add_runtime_dependency(%q<servolux>.freeze, ["~> 0.10.0".freeze])
  s.add_runtime_dependency(%q<file-tail>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<eventmachine>.freeze, ["~> 1.2.7".freeze])
  s.add_runtime_dependency(%q<eventmachine-tail>.freeze, [">= 0.6.4".freeze])
  s.add_runtime_dependency(%q<syslog_protocol>.freeze, ["~> 0.9.2".freeze])
  s.add_runtime_dependency(%q<em-resolv-replace>.freeze, [">= 0".freeze])
end
