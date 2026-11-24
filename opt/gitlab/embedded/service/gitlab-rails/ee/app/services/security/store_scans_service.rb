# frozen_string_literal: true

module Security
  class StoreScansService
    include ::Gitlab::Utils::StrongMemoize

    def self.execute(pipeline, lease_owner: nil)
      new(pipeline, lease_owner: lease_owner).execute
    end

    def initialize(pipeline, lease_owner: nil)
      @pipeline = pipeline
      @lease_owner = lease_owner
    end

    def execute
      return if already_purged?

      ensure_default_tracked_context

      store_security_scans
      store_sbom_scans
      ::Security::AgenticAnalyzer.record_scan(pipeline) if security_report_artifacts.key?('sast')

      schedule_store_reports_worker
      schedule_scan_security_report_secrets_worker
      schedule_update_token_status_worker

      publish_reports_ingested_event
    end

    private

    attr_reader :pipeline, :lease_owner

    delegate :project, to: :pipeline, private: true

    def store_security_scans
      security_report_artifacts.map do |file_type, artifacts|
        StoreGroupedScansService.execute(artifacts, pipeline, file_type, lease_owner: lease_owner)
      end
    end

    def store_sbom_scans
      return [] if sbom_report_artifacts.blank?

      sbom_report_artifacts.map do |file_type, artifacts|
        StoreGroupedSbomScansService.execute(artifacts, pipeline, file_type, lease_owner: lease_owner)
      end
    end

    def already_purged?
      pipeline.security_scans.purged.any?
    end

    # Failsafe for https://gitlab.com/gitlab-org/gitlab/-/issues/612930.
    #
    # A project's default branch is meant to have a tracked context created up front by
    # the project-created handler. When that did not happen (an older project predating the
    # handler, or a missed event), the default context does not exist when the store phase
    # resolves it. The store phase resolves the context find-only, gets nil, and stores the
    # findings with context-unaware (v1) UUIDs. Ingestion then find-or-creates the default
    # context (v2) and re-parses with context-aware (v2) UUIDs, so the ingestion join misses
    # on every finding and the whole slice is dropped.
    #
    # Creating the default context here, before the findings are stored, closes the hole: the
    # store phase resolves the freshly created context and both phases agree on v2. This keeps
    # the default branch on v2 (the intended end state) rather than falling back to v1.
    #
    # Retry contention before storing any findings, so storage and ingestion agree on UUIDs.
    # Other failures retain the best-effort fallback to legacy behavior.
    #
    # Not gated on VAC: ingestion creates the v2 default context whether or not VAC is on.
    def ensure_default_tracked_context
      return unless pipeline.default_branch?
      return if Security::ProjectTrackedContext.for_pipeline(pipeline).tracked.exists?

      result = Security::ProjectTrackedContexts::FindOrCreateService.from_pipeline(pipeline).execute!

      return if result.success?

      Gitlab::AppJsonLogger.warn(
        class: self.class.name,
        message: 'Failed to ensure default tracked context before storing scans',
        error_message: result.message,
        project_id: project.id,
        pipeline_id: pipeline.id
      )
    end

    def grouped_report_artifacts
      # rubocop:disable CodeReuse/ActiveRecord -- the preload matches how this service walks artifacts and it's a unique need
      pipeline.job_artifacts
        .security_reports(file_types: security_report_file_types)
        .preload(:project, job: [:job_source, :pipeline])
        .group_by(&:file_type)
      # rubocop:enable CodeReuse/ActiveRecord
    end
    strong_memoize_attr :grouped_report_artifacts

    def security_report_artifacts
      grouped_report_artifacts.reject { |file_type| file_type == 'cyclonedx' || !parse_report_file?(file_type) }
    end
    strong_memoize_attr :security_report_artifacts

    def sbom_report_artifacts
      grouped_report_artifacts['cyclonedx']&.each_with_object({}) do |artifact, object|
        next if artifact.security_report.blank? || !parse_report_file?(artifact.security_report.type.to_s)

        # Skip SBOM reports from jobs that already have a dependency_scanning security report.
        # This avoids duplicate scanning and ingestion errors.
        # See https://gitlab.com/gitlab-org/gitlab/-/work_items/546429#note_2992962734
        next if job_ids_with_dependency_scanning.include?(artifact.job_id)

        (object[artifact.security_report.type.to_s] ||= []) << artifact
      end
    end
    strong_memoize_attr :sbom_report_artifacts

    def job_ids_with_dependency_scanning
      security_report_artifacts['dependency_scanning']&.map(&:job_id)&.to_set || Set.new
    end
    strong_memoize_attr :job_ids_with_dependency_scanning

    def security_report_file_types
      Enums::Ci::JobArtifact.security_report_and_cyclonedx_report_file_types
    end

    def parse_report_file?(file_type)
      project.feature_available?(Ci::Build::LICENSED_PARSER_FEATURES.fetch(file_type))
    end

    def schedule_store_reports_worker
      return unless Security::Ingestion.ingest_pipeline?(pipeline)

      Gitlab::Redis::SharedState.with do |redis|
        if Security::AgenticAnalyzer.default_branch_scan?(pipeline)
          # A business logic security scan pipeline gets its own slot, so it and the regular
          # default-branch pipeline cannot overwrite each other before the worker runs.
          Security::StoreSecurityReportsByProjectWorker.store_agentic_scan_pipeline(redis, pipeline)
        else
          redis.set(Security::StoreSecurityReportsByProjectWorker.cache_key(project_id: project.id),
            Security::StoreSecurityReportsByProjectWorker.slot_value(pipeline))
        end
      end

      Security::StoreSecurityReportsByProjectWorker.perform_async(project.id)
    end

    def schedule_scan_security_report_secrets_worker
      ScanSecurityReportSecretsWorker.perform_async(pipeline.id) if revoke_secret_detection_token?
    end

    def schedule_update_token_status_worker
      return unless should_update_token_status?

      Security::SecretDetection::GitlabTokenVerificationWorker.perform_async(pipeline.id)
    end

    def should_update_token_status?
      !pipeline.default_branch? &&
        project.security_setting&.validity_checks_enabled &&
        secret_detection_scans_found?
    end

    def revoke_secret_detection_token?
      pipeline.project.public? &&
        ::Gitlab::CurrentSettings.secret_detection_token_revocation_enabled? &&
        secret_detection_scans_found?
    end

    def secret_detection_scans_found?
      pipeline.security_scans.by_scan_types(:secret_detection).any?
    end

    def publish_reports_ingested_event
      ::Gitlab::EventStore.publish(
        Security::ReportsIngestedEvent.new(data: { pipeline_id: pipeline.id })
      )
    end
  end
end
