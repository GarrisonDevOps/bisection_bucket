# frozen_string_literal: true

module Gitlab
  module Security
    module Parsers
      module Validators
        class SarifSchemaValidator
          SUPPORTED_VERSIONS = %w[2.1.0].freeze

          SCHEMA_BASE_PATH = Rails.root.join("ee/app/validators/json_schemas/sarif").freeze

          class << self
            def schema_for(version)
              schemas[version] ||= JSONSchemer.schema(schema_path_for(version))
            end

            private

            def schemas
              Thread.current[:sarif_schema_validators] ||= {}
            end

            def schema_path_for(version)
              SCHEMA_BASE_PATH.join("sarif-schema-#{version}.json")
            end
          end

          def initialize(report_data)
            @report_data = report_data
          end

          def valid?
            errors.empty?
          end

          def errors
            @errors ||= validate!
          end

          private

          attr_reader :report_data

          def validate!
            return ["Expected JSON object but received #{report_data.class}"] unless report_data.is_a?(Hash)
            return pretty_errors if supported_version?

            [format("Unsupported SARIF version. Must be one of: %{versions}",
              versions: SUPPORTED_VERSIONS.join(', '))]
          end

          def supported_version?
            SUPPORTED_VERSIONS.include?(sarif_version)
          end

          def pretty_errors
            raw_errors.map { |error| JSONSchemer::Errors.pretty(error) }
          end

          def raw_errors
            schema.validate(report_data)
          end

          def schema
            self.class.schema_for(sarif_version)
          end

          def sarif_version
            @sarif_version ||= report_data['version']
          end
        end
      end
    end
  end
end
