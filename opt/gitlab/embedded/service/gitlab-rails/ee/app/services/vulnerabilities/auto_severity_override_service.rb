# frozen_string_literal: true

module Vulnerabilities
  # TODO: Refactor to inherit from BaseAutoStateTransitionService to reuse shared methods
  # (user, now, pipeline_link, ensure_bot_user_exists, authorized?, refresh_statistics, insert_notes).
  # See: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/224324#note_3166514629
  class AutoSeverityOverrideService
    include Gitlab::Utils::StrongMemoize
    include Gitlab::InternalEventsTracking
    include SkippedPolicyEvaluationLogging

    BATCH_SIZE = 1000
    AUTO_OVERRIDE_LIMIT = 1000
    HISTOGRAM = :gitlab_security_policies_vulnerability_management_auto_severity_override
    OVERRIDE_EVENT_NAME = 'auto_severity_override_vulnerability_in_project_after_pipeline_run_if_policy_is_set'

    delegate :project, to: :pipeline

    def initialize(pipeline, vulnerability_ids)
      @pipeline = pipeline
      @vulnerability_ids = vulnerability_ids
      @override_count = 0
    end

    def execute
      return success unless ::Security::PolicyAvailability.any_available?(project)

      unless severity_override_checker.policies_present?
        log_skipped_policy_evaluation('auto_severity_override')
        return success
      end

      track_policy_evaluation
      ensure_bot_user_exists
      return success unless authorized?

      measure(HISTOGRAM, callback: method(:log_duration)) do
        vulnerability_reads.each_batch(of: BATCH_SIZE) do |batch|
          break if remaining_budget <= 0

          process_batch(batch)
        end

        refresh_statistics if override_count > 0
      end

      track_severity_override_event
      success(override_count)
    rescue ActiveRecord::ActiveRecordError => e
      ServiceResponse.error(
        message: 'Could not override vulnerability severities',
        reason: 'ActiveRecord error',
        payload: { exception: e }
      )
    end

    private

    attr_reader :pipeline, :vulnerability_ids
    attr_accessor :override_count

    delegate :measure, to: ::Security::SecurityOrchestrationPolicies::ObserveHistogramsService

    def remaining_budget
      AUTO_OVERRIDE_LIMIT - override_count
    end

    def severity_override_checker
      ::Security::Findings::PolicySeverityOverrideChecker.new(project)
    end
    strong_memoize_attr :severity_override_checker

    def process_batch(batch)
      manual_override_ids = vulnerability_ids_with_manual_overrides(batch)
      override_candidates = []

      batch.each do |read|
        break if override_candidates.size >= remaining_budget

        vulnerability = read.vulnerability
        next if manual_override_ids.include?(vulnerability.id)

        best = severity_override_checker.check_with_policy(vulnerability)
        next unless best

        override_candidates << {
          vulnerability: vulnerability,
          read: read,
          new_severity: best[:severity],
          policy: best[:policy],
          original_severity: vulnerability.severity
        }
      end

      return if override_candidates.empty?

      apply_overrides(override_candidates)
      @override_count += override_candidates.size
    end

    def vulnerability_ids_with_manual_overrides(batch)
      vuln_ids = batch.map(&:vulnerability_id)

      Vulnerabilities::SeverityOverride
        .by_vulnerability(vuln_ids)
        .latest
        .manual
        .select(:vulnerability_id)
        .distinct # rubocop:disable CodeReuse/ActiveRecord -- bulk preload query for performance
        .pluck(:vulnerability_id) # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- bounded by BATCH_SIZE (1000)
        .to_set
    end

    def apply_overrides(override_candidates)
      projects = [project]

      ::SecApplicationRecord.feature_flagged_transaction_for(projects) do
        insert_severity_override_records(override_candidates)
        update_vulnerability_severities(override_candidates)
        update_vulnerability_reads(override_candidates, projects)
        schedule_after_commit_jobs(override_candidates)
      end

      try_insert_notes(override_candidates)
      try_audit_severity_changes(override_candidates)
    end

    def insert_severity_override_records(override_candidates)
      records = override_candidates.map do |data|
        {
          vulnerability_id: data[:vulnerability].id,
          original_severity: ::Enums::Vulnerability.severity_levels[data[:original_severity].to_s],
          new_severity: ::Enums::Vulnerability.severity_levels[data[:new_severity].to_s],
          project_id: project.id,
          author_id: user.id,
          security_policy_id: data[:policy].id,
          triggered_by_policy: true,
          created_at: now,
          updated_at: now
        }
      end

      Vulnerabilities::SeverityOverride.insert_all!(records)
    end

    def update_vulnerability_severities(override_candidates)
      override_candidates.group_by { |data| data[:new_severity] }.each do |new_severity, group|
        vuln_ids = group.map { |data| data[:vulnerability].id }

        # rubocop:disable Search/VulnerabilityBulkOperationElasticsearchSync -- ES sync handled by
        # schedule_after_commit_jobs called in the same apply_overrides transaction
        Vulnerability.id_in(vuln_ids).update_all(severity: new_severity, updated_at: now)
        # rubocop:enable Search/VulnerabilityBulkOperationElasticsearchSync
        Vulnerabilities::Finding.by_vulnerability(vuln_ids).update_all(severity: new_severity, updated_at: now)
      end
    end

    def update_vulnerability_reads(override_candidates, projects)
      override_candidates.group_by { |data| data[:new_severity] }.each do |new_severity, group|
        vuln_ids = group.map { |data| data[:vulnerability].id }

        if Feature.enabled?(:turn_off_vulnerability_read_create_db_trigger_function, project)
          Vulnerabilities::Reads::UpsertService
            .new(Vulnerability.id_in(vuln_ids), { severity: new_severity }, projects: projects)
            .execute
        else
          # rubocop:disable Search/VulnerabilityBulkOperationElasticsearchSync -- ES sync handled by
          # schedule_after_commit_jobs called in the same apply_overrides transaction
          Vulnerabilities::Read.by_vulnerabilities(vuln_ids).update_all(severity: new_severity)
          # rubocop:enable Search/VulnerabilityBulkOperationElasticsearchSync
        end
      end
    end

    def schedule_after_commit_jobs(override_candidates)
      vulnerability_ids_to_update = override_candidates.map { |data| data[:vulnerability].id }
      vulnerabilities_to_update = Vulnerability.id_in(vulnerability_ids_to_update)

      ::SecApplicationRecord.current_transaction.after_commit do
        Vulnerabilities::BulkEsOperationService.new(vulnerabilities_to_update).execute(&:itself)
        Vulnerabilities::Findings::RiskScoreCalculationService.new(vulnerability_ids_to_update).execute
      end
    end

    def try_insert_notes(override_candidates)
      insert_notes(override_candidates)
    rescue ActiveRecord::ActiveRecordError => e
      Gitlab::AppJsonLogger.error(
        message: 'Failed to insert system notes for auto-severity-override',
        project_id: project.id,
        pipeline_id: pipeline.id,
        exception: e.message
      )
    end

    def try_audit_severity_changes(override_candidates)
      audit_severity_changes(override_candidates)
    rescue StandardError => e
      Gitlab::AppJsonLogger.error(
        message: 'Failed to create audit events for auto-severity-override',
        project_id: project.id,
        pipeline_id: pipeline.id,
        exception_class: e.class.name,
        exception: e.message
      )
    end

    def insert_notes(override_candidates)
      note_attrs = override_candidates.map do |data|
        {
          noteable_type: "Vulnerability",
          noteable_id: data[:vulnerability].id,
          project_id: project.id,
          system: true,
          note: formatted_system_note(data),
          author_id: user.id,
          created_at: now,
          updated_at: now
        }
      end

      Note.transaction do
        results = Note.insert_all!(note_attrs, returning: %w[id])
        SystemNoteMetadata.insert_all!(note_metadata_attrs(results))
      end
    end

    def formatted_system_note(data)
      ::SystemNotes::VulnerabilitiesService.formatted_note(
        transition: 'changed',
        to_value: data[:new_severity],
        reason: nil,
        comment: format(
          _("Auto-overridden by the vulnerability management policy named '%{policy_name}' " \
            "in pipeline %{pipeline_link}."),
          policy_name: data[:policy].name,
          pipeline_link: pipeline_link
        ),
        attribute: 'severity',
        from_value: data[:original_severity]
      )
    end

    def note_metadata_attrs(results)
      results.map do |row|
        {
          note_id: row['id'],
          action: 'vulnerability_severity_changed',
          created_at: now,
          updated_at: now
        }
      end
    end

    def audit_severity_changes(override_candidates)
      override_candidates.group_by { |data| data[:new_severity] }.each do |new_severity, group|
        attrs = group.map do |data|
          {
            old_severity: data[:original_severity],
            project: project,
            vulnerability: data[:vulnerability]
          }
        end

        SeverityOverrideAuditService.new(
          vulnerabilities_audit_attrs: attrs,
          now: now,
          current_user: user,
          new_severity: new_severity
        ).execute
      end
    end

    def vulnerability_reads
      Vulnerabilities::Read
        .by_vulnerabilities(vulnerability_ids)
        .with_states(actionable_states)
        .with_findings_scanner_and_identifiers
    end

    def actionable_states
      ::Enums::Vulnerability.vulnerability_states.except(:resolved, :dismissed).values
    end

    def authorized?
      Ability.allowed?(user, :create_vulnerability_state_transition, project)
    end

    def ensure_bot_user_exists
      ::Security::Orchestration::CreateBotService.new(project, nil, skip_authorization: true).execute
    end

    def user
      @user ||= project.security_policy_bot
    end

    def now
      @now ||= Time.current.utc
    end

    def pipeline_link
      "[#{pipeline.id}](#{pipeline_url})"
    end
    strong_memoize_attr :pipeline_link

    def pipeline_url
      Gitlab::UrlBuilder.build(pipeline)
    end

    def refresh_statistics
      Vulnerabilities::Statistics::AdjustmentWorker.perform_async([project.id])
    end

    def success(count = 0)
      ServiceResponse.success(payload: { count: count })
    end

    def track_policy_evaluation
      track_internal_event(
        'evaluate_vulnerability_management_policy_in_project',
        project: project,
        additional_properties: { label: 'auto_severity_override' }
      )
    end

    def track_severity_override_event
      return if override_count == 0

      track_internal_event(
        OVERRIDE_EVENT_NAME,
        project: project,
        additional_properties: { value: override_count }
      )
    end

    def log_duration(duration)
      return if override_count == 0

      Gitlab::AppJsonLogger.info(
        class: self.class.name,
        project_id: project.id,
        pipeline_id: pipeline.id,
        policy_auto_severity_override_vulnerabilities_overridden: override_count,
        policy_auto_severity_override_duration_s: duration
      )
    end
  end
end
