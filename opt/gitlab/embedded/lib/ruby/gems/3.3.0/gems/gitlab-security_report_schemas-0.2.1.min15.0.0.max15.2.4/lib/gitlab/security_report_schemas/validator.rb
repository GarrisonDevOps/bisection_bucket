# frozen_string_literal: true

require "json_schemer"

require_relative "schema"

module Gitlab
  module SecurityReportSchemas
    # Takes the data to be validated along with the
    # report type and version.
    class Validator
      UNSUPPORTED_SCHEMA_TEMPLATE = "Version %<version>s for report type %<report_type>s is unsupported, " \
                                    "supported versions for this report type are: %<supported_versions>s"

      DEPRECATED_SCHEMA_TEMPLATE = "Version %<version>s for report type %<report_type>s has been deprecated, " \
                                   "supported versions for this report type are: %<supported_versions>s"

      FALLBACK_USED_TEMPLATE = "This report uses a supported MAJOR.MINOR version but the PATCH doesn't match " \
                               "any vendored schema version. Validation is done against version %<fallback>s"

      def initialize(data, report_type, version)
        @data = data
        @report_type = report_type
        @version = version
      end

      def valid?
        errors.empty?
      end

      def errors
        @errors ||= schema.supported? ? schema_errors : [unsupported_schema_error]
      end

      def warnings
        [].tap do |warn|
          warn << deprecated_schema_warning_message if schema.deprecated?
          warn << fallback_schema_used_warning_message if schema.fallback?
        end
      end

      delegate :schema_ver_version, to: :schema

      private

      attr_reader :data, :report_type, :version

      def schema_errors
        validation_result.map { |error| JSONSchemer::Errors.pretty(error) }
      end

      def unsupported_schema_error
        formatted_message(UNSUPPORTED_SCHEMA_TEMPLATE, SecurityReportSchemas.supported_versions)
      end

      def deprecated_schema_warning_message
        formatted_message(DEPRECATED_SCHEMA_TEMPLATE, SecurityReportSchemas.maintained_versions)
      end

      def fallback_schema_used_warning_message
        format(FALLBACK_USED_TEMPLATE, fallback: schema_ver_version)
      end

      def formatted_message(template, supported_versions)
        format(template,
               version: schema_ver_version,
               report_type: report_type,
               supported_versions: supported_versions.map(&:to_s))
      end

      def validation_result
        @validation_result ||= schema.validate(data)
      end

      def schema
        @schema ||= Schema.new(report_type, version)
      end
    end
  end
end
