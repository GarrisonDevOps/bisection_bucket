# frozen_string_literal: true

module Sbom
  module Ingestion
    class IngestReportsService
      include Gitlab::ExclusiveLeaseHelpers
      include Gitlab::Utils::StrongMemoize

      # Typical job finishes in 1-2 minutes, but has been observed
      # to take up to 20 minutes in the worst case.
      LEASE_TTL = 30.minutes

      # 10 retries at 6 seconds each will allow 95% of jobs to acquire a lease
      # without raising FailedToObtainLockError. When waiting for exceptionally long jobs,
      # we'll allow the job to raise and be retried by sidekiq.
      LEASE_TRY_AFTER = 6.seconds

      def self.execute(pipeline)
        new(pipeline).execute
      end

      def initialize(pipeline)
        @pipeline = pipeline
      end

      def execute
        in_lock(lease_key, ttl: LEASE_TTL, sleep_sec: LEASE_TRY_AFTER) do
          strategy_class.new(valid_sbom_reports, project, pipeline).execute

          track_sbom_report_errors
        end
      end

      private

      def strategy_class
        if sbom_sources.include?(:container_scanning_for_registry)
          ExecutionStrategy::ContainerScanningForRegistry
        else
          ExecutionStrategy::Default
        end
      end

      attr_reader :pipeline

      delegate :project, to: :pipeline, private: true

      def sbom_sources
        sources = Set.new

        valid_sbom_reports.each do |report|
          sources << report&.source&.source_type
        end

        sources.to_a.compact
      end

      def all_sbom_reports
        @all_sbom_reports ||= pipeline.sbom_reports(self_and_project_descendants: true).reports
      end

      def track_sbom_report_errors
        return unless sbom_report_errors

        pipeline.set_sbom_report_ingestion_errors(sbom_report_errors)
      end

      # Returns the valid reports, split into one report for each path of their components, because ingestion reads
      # the file of each row from the source of its report.
      def valid_sbom_reports
        all_sbom_reports.select(&:valid?).flat_map do |report|
          report.third_party_sbom_support ? report.split_by_path : [report]
        end
      end
      strong_memoize_attr :valid_sbom_reports

      def sbom_report_errors
        return unless invalid_sbom_reports.any?

        invalid_sbom_reports.map(&:errors)
      end
      strong_memoize_attr :sbom_report_errors

      def invalid_sbom_reports
        all_sbom_reports.reject(&:valid?)
      end
      strong_memoize_attr :invalid_sbom_reports

      def lease_key
        Sbom::Ingestion.project_lease_key(project.id)
      end
    end
  end
end
