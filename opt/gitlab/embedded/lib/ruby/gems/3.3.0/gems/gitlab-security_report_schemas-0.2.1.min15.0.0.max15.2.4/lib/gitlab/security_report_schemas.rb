# frozen_string_literal: true

require "pathname"
require "active_support/all"
require_relative "security_report_schemas/configuration"
require_relative "security_report_schemas/schema_ver"
require_relative "security_report_schemas/version"
require_relative "security_report_schemas/validator"

module Gitlab
  # The `gitlab-security_report_schemas` gem contains JSON schemas and utilities
  # for GitLab security reports.
  module SecurityReportSchemas
    class Error < StandardError; end

    SCHEMA_PATH_REGEX = %r{.+schemas/(\d+\.\d+\.\d+)$}

    class << self
      # Returns the list of schema versions available including the deprecated ones.
      def supported_versions
        @supported_versions ||= schema_directories.map { |path_name| path_name_to_version(path_name) }.sort
      end

      # Returns the list of actively maintained schemas excluding the ones marked as deprecated.
      def maintained_versions
        @maintained_versions ||= supported_versions - deprecated_versions
      end

      def deprecated_versions
        @deprecated_versions ||= configuration.deprecated_versions.map { |version| SchemaVer.new(version) }
      end

      def schema_files
        schema_directories.flat_map { |directory| directory.children.select(&:file?) }
                          .map { |schema_path| schema_path.relative_path_from(root_path) }
      end

      def schema_directories
        schemas_path.children.select(&:directory?)
      end

      def root_path
        @root_path ||= Pathname.new(__dir__).join("..", "..")
      end

      def configure(&block)
        flush_memoized_methods!

        block.call(configuration)
      end

      def configuration
        @configuration ||= Configuration.new
      end

      delegate :schemas_path, to: :configuration

      private

      def flush_memoized_methods!
        @deprecated_versions = @maintained_versions = nil
      end

      def path_name_to_version(path_name)
        version = path_name.to_s.match(SCHEMA_PATH_REGEX).captures.first

        SchemaVer.new(version)
      end
    end
  end
end
