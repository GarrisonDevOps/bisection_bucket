# frozen_string_literal: true

module Ci
  module PipelineArtifacts
    class CoverageReportService
      include Gitlab::Utils::StrongMemoize

      def initialize(pipeline)
        @pipeline = pipeline
      end

      def execute
        return if report.empty?

        Ci::PipelineArtifact.create_or_replace_for_pipeline!(**pipeline_artifact_params).tap do |pipeline_artifact|
          Gitlab::AppLogger.info(log_params(pipeline_artifact))
        end
      end

      private

      attr_reader :pipeline

      def generator
        strong_memoize(:generator) do
          Gitlab::Ci::Reports::CoverageReportGenerator.new(pipeline)
        end
      end

      def report
        strong_memoize(:report) do
          generator.report
        end
      end

      def pipeline_artifact_params
        {
          pipeline: pipeline,
          file_type: :code_coverage,
          file: carrierwave_file,
          size: carrierwave_file['tempfile'].size,
          locked: pipeline.locked
        }
      end

      def carrierwave_file
        strong_memoize(:carrier_wave_file) do
          CarrierWaveStringFile.new_file(
            file_content: Gitlab::Json.dump(
              'files' => report.files,
              Ci::PipelineArtifact::SOURCE_ACCESS_KEY => generator.source_access
            ),
            filename: Ci::PipelineArtifact::DEFAULT_FILE_NAMES.fetch(:code_coverage),
            content_type: 'application/json'
          )
        end
      end

      def log_params(pipeline_artifact)
        {
          project_id: pipeline.project_id,
          pipeline_id: pipeline.id,
          pipeline_artifact_id: pipeline_artifact.id,
          message: "Created code coverage for pipeline."
        }
      end
    end
  end
end
