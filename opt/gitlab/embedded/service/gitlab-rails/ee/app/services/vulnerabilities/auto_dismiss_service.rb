# frozen_string_literal: true

module Vulnerabilities
  class AutoDismissService < BaseAutoStateTransitionService
    BATCH_SIZE = 1000
    AUTO_DISMISS_LIMIT = 1000
    HISTOGRAM = :gitlab_security_policies_vulnerability_management_auto_dismiss

    def initialize(pipeline, vulnerability_ids)
      super
      @processed_count = 0
      @dismissed_count = 0
    end

    def execute
      return success unless ::Security::PolicyAvailability.any_available?(project)

      if policies.blank?
        log_skipped_policy_evaluation('auto_dismiss')
        return success
      end

      track_policy_evaluation

      measure(HISTOGRAM, callback: method(:log_duration)) do
        super do
          vulnerability_reads.each_batch(of: BATCH_SIZE) do |batch|
            break if remaining_budget <= 0

            process_batch(batch)
          end

          dismissed_count
        end
      end
    end

    private

    attr_accessor :processed_count, :dismissed_count

    delegate :measure, to: ::Security::SecurityOrchestrationPolicies::ObserveHistogramsService

    def log_duration(duration)
      return if processed_count == 0

      Gitlab::AppJsonLogger.info(
        class: self.class.name,
        project_id: project.id,
        pipeline_id: pipeline.id,
        policy_auto_dismiss_vulnerabilities_processed: processed_count,
        policy_auto_dismiss_vulnerabilities_dismissed: dismissed_count,
        policy_auto_dismiss_duration_s: duration
      )
    end

    def process_batch(batch)
      @processed_count += batch.size
      rules_by_vulnerability = batch.index_with do |read|
        rules.find { |rule| rule.match?(read.vulnerability) }
      end.compact

      vulnerabilities_to_dismiss = rules_by_vulnerability.keys.first(remaining_budget)

      perform_state_transition(vulnerabilities_to_dismiss, rules_by_vulnerability)
      @dismissed_count += vulnerabilities_to_dismiss.size
    end

    def remaining_budget
      AUTO_DISMISS_LIMIT - dismissed_count
    end

    def vulnerability_reads
      super.with_findings_scanner_and_identifiers
    end

    def policies
      project
        .vulnerability_management_policies
        .auto_dismiss_policies.including_rules
    end
    strong_memoize_attr :policies

    def rules
      policies
        .flat_map(&:vulnerability_management_policy_rules)
        .select(&:type_detected?)
    end
    strong_memoize_attr :rules

    def update_transaction(vulnerabilities_to_dismiss, rules_by_vulnerability)
      ::SecApplicationRecord.feature_flagged_transaction_for([project]) do
        Vulnerabilities::StateTransition.insert_all!(
          state_transition_attrs(vulnerabilities_to_dismiss, rules_by_vulnerability)
        )

        vulnerabilities_to_update = Vulnerability.id_in(vulnerabilities_to_dismiss.map(&:vulnerability_id))
        vulnerabilities_to_update.update_all(
          state: :dismissed,
          dismissed_by_id: user.id,
          dismissed_at: now,
          updated_at: now,
          auto_resolved: false
        )

        update_vulnerability_reads(vulnerabilities_to_dismiss, rules_by_vulnerability)

        Vulnerability.current_transaction.after_commit do
          Vulnerabilities::BulkEsOperationService.new(vulnerabilities_to_update).execute
          trigger_webhook_events(vulnerabilities_to_update)
        end
      end
    end

    # Updates vulnerability reads with per-vulnerability dismissal reasons based on
    # the matching policy rule, rather than using a single global reason.
    def update_vulnerability_reads(vulnerabilities_to_dismiss, rules_by_vulnerability)
      grouped_by_reason = vulnerabilities_to_dismiss.group_by do |vuln_read|
        dismissal_reason_for_vulnerability(vuln_read, rules_by_vulnerability)
      end

      grouped_by_reason.each do |reason_enum_value, vuln_reads|
        vuln_ids = vuln_reads.map(&:vulnerability_id)
        vulnerabilities_for_reason = Vulnerability.id_in(vuln_ids)

        if Feature.enabled?(:turn_off_vulnerability_read_create_db_trigger_function, project)
          Vulnerabilities::Reads::UpsertService.new(vulnerabilities_for_reason,
            { state: :dismissed, dismissal_reason: reason_enum_value },
            projects: project
          ).execute
        else
          # When the trigger is active, it handles state updates but not dismissal_reason
          # The `insert_or_update_vulnerability_reads` database trigger does not
          # update the dismissal_reason and we are moving away from using
          # database triggers to keep tables up to date.
          Vulnerabilities::Read
            .by_vulnerabilities(vulnerabilities_for_reason)
            .update_all(state: :dismissed, dismissal_reason: reason_enum_value) # rubocop:disable Search/VulnerabilityBulkOperationElasticsearchSync -- ES sync handled in the after_commit block within update_transaction method above
        end
      end
    end

    def internal_event_name
      'auto_dismiss_vulnerability_in_project_after_pipeline_run_if_policy_is_set'
    end

    def track_policy_evaluation
      track_internal_event(
        'evaluate_vulnerability_management_policy_in_project',
        project: project,
        additional_properties: { label: 'auto_dismiss' }
      )
    end

    def target_state
      :dismissed
    end

    def formatted_system_note(vulnerability, rules_by_vulnerability_map)
      reason = dismissal_reason_for_rule(rules_by_vulnerability_map[vulnerability])
      ::SystemNotes::VulnerabilitiesService.formatted_note(
        transition: 'changed',
        to_value: :dismissed,
        reason: reason.to_s.titleize,
        comment: comment(vulnerability, rules_by_vulnerability_map)
      )
    end

    def note_metadata_action
      'vulnerability_dismissed'
    end

    def comment(vulnerability, rules_by_vulnerability)
      rule = rules_by_vulnerability[vulnerability]
      format(
        _("Auto-dismissed by the vulnerability management policy named '%{policy_name}' " \
          "as the vulnerability matched the policy criteria in pipeline %{pipeline_link}."),
        policy_name: rule.security_policy.name,
        pipeline_link: pipeline_link
      )
    end

    # Returns the dismissal reason string from the policy that owns the given rule.
    def dismissal_reason_for_rule(rule)
      first_policy_reason = policies.first.dismissal_reason
      return first_policy_reason unless rule

      rule.security_policy.dismissal_reason || first_policy_reason
    end

    # Returns the dismissal reason enum value for a specific vulnerability read,
    # based on the matching rule's policy.
    def dismissal_reason_for_vulnerability(vulnerability, rules_by_vulnerability)
      rule = rules_by_vulnerability[vulnerability]
      reason = dismissal_reason_for_rule(rule)
      Vulnerabilities::DismissalReasonEnum.values[reason.to_sym]
    end

    def base_error_message
      'Could not dismiss vulnerabilities'
    end

    def state_transition_base_attrs(vulnerability, rules_by_vulnerability)
      { dismissal_reason: dismissal_reason_for_vulnerability(vulnerability, rules_by_vulnerability) }
    end
  end
end
