# frozen_string_literal: true

require "json_schemer"

module Gitlab
  module SecurityReportSchemas
    # Schema related logic
    class Schema
      attr_reader :report_type, :version

      CROSS_COMPLIANT_SCHEMAS = { api_fuzzing: :dast }.freeze

      def initialize(report_type, version)
        @report_type = report_type
        @version = version
      end

      delegate :validate, to: :schemer
      delegate :supported?, :deprecated?, :fallback?, to: :schema_ver
      delegate :version, to: :schema_ver, prefix: true

      private

      delegate :schemas_path, to: SecurityReportSchemas, private: true

      def schemer
        @schemer ||= JSONSchemer.schema(pathname)
      end

      def pathname
        Pathname.new(schema_file_path)
      end

      def schema_file_path
        schemas_path.join(schema_ver, schema_file_name)
      end

      def schema_file_name
        "#{schema_name.to_s.dasherize}-report-format.json"
      end

      def schema_name
        CROSS_COMPLIANT_SCHEMAS.fetch(report_type.to_sym, report_type)
      end

      def schema_ver
        @schema_ver ||= SchemaVer.new!(version)
      end
    end
  end
end
