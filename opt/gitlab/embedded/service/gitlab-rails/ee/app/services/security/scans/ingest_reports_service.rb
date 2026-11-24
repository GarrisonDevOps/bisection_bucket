# frozen_string_literal: true

module Security
  module Scans
    class IngestReportsService
      include Gitlab::ExclusiveLeaseHelpers
      include ::Gitlab::Utils::StrongMemoize

      TTL_REPORT_INGESTION = 1.hour

      def self.execute(pipeline)
        new(pipeline).execute
      end

      def initialize(pipeline)
        @pipeline = pipeline
      end

      def execute
        return unless project.can_store_security_reports?
        return unless root_pipeline.security_reports_ready_for_ingestion?
        return if already_ingested?

        pipelines_with_security_reports.each do |pipeline_to_process|
          process_pipeline(pipeline_to_process)
        end
      end

      private

      attr_reader :pipeline

      delegate :project, to: :pipeline, private: true

      def process_pipeline(pipeline_to_process)
        ::Security::StoreScansWorker.perform_async(pipeline_to_process.id)
        ::Security::ProcessScanEventsWorker.perform_async(pipeline_to_process.id)
      end

      def scans_cache_key
        sha = security_builds
              .sort_by(&:id)
              .map { |build| "#{build.id}:#{build.updated_at}" }
              .join('|')
              .then { |value| Digest::SHA512.hexdigest(value) }
        "security:report:ingest:#{sha}"
      end

      def already_ingested?
        ::Gitlab::Redis::SharedState.with do |redis|
          !redis.set(scans_cache_key, 'OK', nx: true, ex: TTL_REPORT_INGESTION)
        end
      end

      def pipelines_in_hierarchy
        root_pipeline.self_and_project_descendants
      end
      strong_memoize_attr :pipelines_in_hierarchy

      # rubocop:disable CodeReuse/ActiveRecord -- Fixing N+1 until we convert to direct sql query
      def security_builds
        pipeline_ids = pipelines_in_hierarchy.map(&:id)
        Ci::Build.in_pipelines(pipeline_ids).latest.includes(:job_definition).select(&:security_job?)
      end
      strong_memoize_attr :security_builds

      def pipelines_with_security_reports
        pipelines_ids_with_security_jobs = security_builds.map(&:pipeline_id).uniq
        pipelines_in_hierarchy.select { |p| pipelines_ids_with_security_jobs.include?(p.id) }
      end
      # rubocop:enable CodeReuse/ActiveRecord

      def root_pipeline
        pipeline.root_ancestor
      end
    end
  end
end
