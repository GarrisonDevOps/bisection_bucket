# frozen_string_literal: true

module Types
  module Security
    class AnalyzerTypeEnum < Types::BaseEnum
      graphql_name 'AnalyzerTypeEnum'
      description 'Enum for types of analyzers '

      ANALYZER_CONFIGS = {
        **Enums::Security.analyzer_types.except(:secret_detection, :container_scanning)
          .transform_values { |_| {} },

        secret_detection_pipeline_based: {
          description: "Secret detection analyzer."
        },
        container_scanning_pipeline_based: {
          description: "Container scanning analyzer."
        },
        secret_detection_secret_push_protection: {
          description: "Secret push protection. Managed via project security settings."
        },
        container_scanning_for_registry: {
          description: "Container scanning for registry. Managed via project security settings."
        },
        container_scanning: {
          description: "Any kind of container scanning."
        },
        secret_detection: {
          description: "Any kind of secret detection."
        }
      }.freeze

      ANALYZER_CONFIGS.each do |analyzer_type, config|
        description = config[:description] || "#{analyzer_type.to_s.humanize} analyzer."

        value analyzer_type.to_s.upcase,
          value: analyzer_type.to_s,
          description: description
      end
    end
  end
end
