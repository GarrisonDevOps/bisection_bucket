# frozen_string_literal: true

module Dependencies
  module ExportSerializers
    module Sbom
      class PipelineService
        include ::Sbom::Exporters::WriteBlob

        SchemaValidationError = Class.new(StandardError)

        def initialize(dependency_list_export, _sbom_occurrences)
          @dependency_list_export = dependency_list_export

          @pipeline = dependency_list_export.pipeline
          @project = pipeline.project
        end

        def generate(&block)
          write_json_blob(sbom_data, &block)
        end

        private

        def sbom_data
          response = serializer_service.execute
          record_failed_status(response.errors) if response.error?

          response.payload
        end

        def serializer_service
          @service ||= ::Sbom::ExportSerializers::JsonService.new(merged_report)
        end

        def merged_report
          ::Sbom::MergeReportsService.new(
            pipeline.sbom_reports.valid_reports,
            license_override_applicator: license_override_applicator
          ).execute
        end

        def license_override_applicator
          @license_override_applicator ||= ::Security::LicenseOverrideApplicator.new(project)
        end

        def record_failed_status(errors)
          ::Gitlab::AppLogger.warn(
            message: "SBoM report failed schema validation during export",
            errors: errors.join(', '),
            pipeline_id: pipeline.id
          )

          ::Gitlab::Metrics.counter(
            :sbom_schema_report_export_validation_failures_total,
            'Count of SBoM schema validation failures during report export'
          ).increment(
            project_id: pipeline.project_id,
            pipeline_id: pipeline.id
          )
        end

        attr_reader :dependency_list_export, :scanner, :pipeline, :project
      end
    end
  end
end
