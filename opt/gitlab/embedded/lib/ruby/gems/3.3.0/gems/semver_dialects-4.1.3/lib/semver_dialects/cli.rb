# frozen_string_literal: true

require 'thor'

module SemverDialects
  # Handle the application command line parsing
  # and the dispatch to various command objects
  #
  # @api public
  class CLI < Thor
    # Error raised by this runner
    Error = Class.new(StandardError)

    desc 'version', 'semver_dialects version'
    def version
      require_relative 'version'
      puts "v#{SemverDialects::VERSION}"
    end
    map %w[--version -v] => :version

    desc 'check_version TYPE VERSION CONSTRAINT', 'Command description...'
    method_option :help, aliases: '-h', type: :boolean,
                         desc: 'Display usage information'
    def check_version(type, version, constraint)
      if options[:help]
        invoke :help, ['check_version']
      else
        require_relative 'commands/check_version'
        ecode = SemverDialects::Commands::CheckVersion.new(type, version, constraint, options).execute
        exit(ecode)
      end
    end

    desc 'sort TYPE VERSIONS...', 'Sort a list of versions according to the specified package type'
    method_option :help, aliases: '-h', type: :boolean,
                         desc: 'Display usage information'
    method_option :json, type: :boolean,
                         desc: 'Output results in JSON format'
    def sort(type, *versions)
      if options[:help]
        invoke :help, ['sort']
      else
        require_relative 'commands/sort_versions'
        ecode = SemverDialects::Commands::SortVersions.new(type, versions, options).execute
        exit(ecode)
      end
    end
  end
end
