# frozen_string_literal: true

module Sbom
  class ScheduleIngestReportsService
    include Gitlab::Utils::StrongMemoize

    def self.execute(pipeline)
      new(pipeline).execute
    end

    def initialize(pipeline)
      @pipeline = pipeline
    end

    def execute
      return unless pipeline.project.namespace.ingest_sbom_reports_available?

      return if !pipeline.default_branch? && Security::VAC.disabled?(pipeline.project)

      return unless root_pipeline.security_reports_ready_for_ingestion?
      return unless any_pipeline_has_sbom_reports?

      ::Sbom::IngestReportsWorker.perform_async(root_pipeline.id)
    end

    private

    attr_reader :pipeline

    def any_pipeline_has_sbom_reports?
      root_pipeline.builds_in_self_and_project_descendants
        .with_artifacts(::Ci::JobArtifact.of_report_type(:sbom)).any?
    end

    def root_pipeline
      @root_pipeline ||= pipeline.root_ancestor
    end
  end
end
