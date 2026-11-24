# frozen_string_literal: true

require_relative '../command'
require_relative '../../semver_dialects'
require 'json'

module SemverDialects
  module Commands
    # The sort command implementation
    class SortVersions < SemverDialects::Command
      def initialize(type, versions, options) # rubocop:disable Lint/MissingSuper
        @type = type.downcase
        @versions = versions
        @options = options
      end

      def execute(_input: $stdin, output: $stdout)
        sorted_versions = []
        invalid_versions = []

        @versions.each do |version|
          parsed_version = SemverDialects.parse_version(@type, version)
          sorted_versions << parsed_version
        rescue SemverDialects::InvalidVersionError, SemverDialects::UnsupportedVersionError => e
          invalid_versions << { version:, error: e.message }
        end

        sorted_versions.sort!

        if @options[:json]
          result = {
            versions: sorted_versions.map(&:to_s),
            invalid: invalid_versions.map { |v| v[:version] }
          }
          output.puts JSON.generate(result)
        else
          invalid_versions.each do |invalid|
            output.puts "Warning: Invalid version '#{invalid[:version]}' - #{invalid[:error]}"
          end
          output.puts "Sorted versions: #{sorted_versions.map(&:to_s).join(', ')}"
        end

        0
      end
    end
  end
end
