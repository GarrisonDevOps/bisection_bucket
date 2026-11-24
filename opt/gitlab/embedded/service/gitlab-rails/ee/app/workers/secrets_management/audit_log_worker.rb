# frozen_string_literal: true

module SecretsManagement
  class AuditLogWorker
    include ApplicationWorker

    data_consistency :delayed
    feature_category :secrets_management
    urgency :low
    # Identical payloads can only come from OpenBao re-sending the same audit
    # line, so deduplicating on the raw JSON argument is safe and desirable.
    deduplicate :until_executed
    idempotent!
    defer_on_database_health_signal :gitlab_main_org, [:project_audit_events, :group_audit_events], 1.minute,
      indicators: Gitlab::Database::HealthStatus::GLOBAL_INDICATORS

    # Comfortably outlives both the retry schedule and OpenBao re-sends of
    # the same audit line, without accumulating a key per secrets read for
    # longer than needed.
    PROCESSED_MARKER_TTL = 6.hours

    def perform(raw_audit_log_json)
      audit_log = AuditLog.new(raw_audit_log_json)

      # Nothing to inherit: the OpenBao request that enqueued this resolves no
      # project or namespace. `with_context` only reaches log lines written inside
      # the block, so a job that fails before the audit write needs the job hash.
      # LabKit has a standard field for the project path, none for a namespace path.
      log_extra_metadata_on_done(Labkit::Fields::GL_PROJECT_PATH, audit_log.project.full_path) if audit_log.project
      log_extra_metadata_on_done(:group_path, audit_log.group.full_path) if audit_log.group

      with_context({ project: audit_log.project, namespace: audit_log.group }.compact) do
        write_audit_log(audit_log)
        emit_billing_event(audit_log)
      end
    end

    private

    # Sidekiq delivers at least once: a retry or a crash-recovery redelivery
    # can re-run a job whose audit write already committed, and the audit
    # tables have no natural-key guard against a second insert. A Redis
    # marker keyed on OpenBao's request id - set only after a successful
    # write - makes the write effectively-once.
    def write_audit_log(audit_log)
      marker = processed_marker_key(audit_log)
      return audit_log.log! unless marker

      IdempotencyCache.ensure_idempotency(marker, PROCESSED_MARKER_TTL) { audit_log.log! }
    end

    # The billing emit needs its own marker: the streaming path tolerates a
    # re-run since CustomersDot dedupes on the event id, but local persistence's
    # RecordAggregateService never sees that id and would count the read twice.
    def emit_billing_event(audit_log)
      marker = processed_marker_key(audit_log, 'billing')
      return emit_secrets_read(audit_log) unless marker
      # Not rescued: nothing is billed yet, so a Redis failure here should fail the job
      # and let Sidekiq retry. The audit marker stops the retry re-writing the audit row.
      return if IdempotencyCache.already_completed?(marker)

      mark_billing_emitted(marker) if emit_secrets_read(audit_log)
    end

    def emit_secrets_read(audit_log)
      BillableEvents::SecretsReadEmitter.emit!(audit_log)
      true
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(e)
      false
    end

    # Rescued, unlike the lookup above: the read is already billed, so a retry would
    # count it twice.
    def mark_billing_emitted(marker)
      IdempotencyCache.new(marker, PROCESSED_MARKER_TTL).mark_as_completed!
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(e)
    end

    def processed_marker_key(audit_log, stage = nil)
      request_id = audit_log.parsed_json.dig('request', 'id')
      return if request_id.blank?

      ['secrets_management:audit_log_worker', stage, request_id].compact.join(':')
    end
  end
end
