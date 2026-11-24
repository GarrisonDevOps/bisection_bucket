# frozen_string_literal: true

module EE
  module Enums
    module Ci
      module JobArtifact
        extend ActiveSupport::Concern

        EE_REPORT_FILE_TYPES = {
          license_scanning: %w[license_scanning].freeze,
          dependency_list: %w[dependency_scanning].freeze,
          metrics: %w[metrics].freeze,
          container_scanning: %w[container_scanning].freeze,
          cluster_image_scanning: %w[cluster_image_scanning].freeze,
          dast: %w[dast].freeze,
          requirements: %w[requirements].freeze,
          requirements_v2: %w[requirements_v2].freeze,
          coverage_fuzzing: %w[coverage_fuzzing].freeze,
          api_fuzzing: %w[api_fuzzing].freeze,
          browser_performance: %w[browser_performance performance].freeze,
          sbom: %w[cyclonedx].freeze,
          sarif: %w[sarif].freeze
        }.freeze

        def self.ee_report_file_types
          EE_REPORT_FILE_TYPES
        end
      end
    end
  end
end
