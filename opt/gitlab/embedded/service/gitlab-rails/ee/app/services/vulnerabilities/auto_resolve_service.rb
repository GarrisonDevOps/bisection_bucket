# frozen_string_literal: true

module Vulnerabilities
  class AutoResolveService < BaseAutoStateTransitionService
    def initialize(pipeline, vulnerability_ids, budget)
      super(pipeline, vulnerability_ids)
      @budget = budget
    end

    def execute
      if policies.blank?
        log_skipped_policy_evaluation('auto_resolve')
        return success
      end

      track_policy_evaluation

      super do
        perform_state_transition(vulnerabilities_to_resolve, rules_by_vulnerability)
        vulnerabilities_to_resolve.size
      end
    end

    private

    attr_reader :budget

    def vulnerabilities_to_resolve
      rules_by_vulnerability.keys.first(budget)
    end

    def rules_by_vulnerability
      vulnerability_reads.index_with do |read|
        rules.find { |rule| rule.match?(read) }
      end.compact
    end
    strong_memoize_attr :rules_by_vulnerability

    def policies
      project
        .vulnerability_management_policies
        .auto_resolve_policies.including_rules
    end
    strong_memoize_attr :policies

    def rules
      policies
        .flat_map(&:vulnerability_management_policy_rules)
        .select(&:type_no_longer_detected?)
    end
    strong_memoize_attr :rules

    def update_transaction(vulnerabilities_to_resolve, rules_by_vulnerability)
      Vulnerability.feature_flagged_transaction_for(project) do
        Vulnerabilities::StateTransition.insert_all!(
          state_transition_attrs(vulnerabilities_to_resolve, rules_by_vulnerability)
        )

        # The caller (Security::Ingestion::MarkAsResolvedService) operates on ALL Vulnerability::Read rows
        # narrowed by scanner type in batches of 1000. If we apply any sort of limit here then this poses a problem:
        # 1. A policy is set to auto-resolve crical SAST vulnerabiliites.
        # 2. In the first 1000 SAST Vulnerability::Read rows there's one critical vulnerability.
        # 3. There's no guarantee that the critical vulnerability is going to be among the first 100 rows

        # Theoretically we could sort them according to severity but this will also not work if you have a policy
        # that auto-resolves Critical and Low SAST vulnerabilities. First 100 will most certainly contain the Critical
        # ones but the Low ones are going to be at the end of the collection
        vulnerabilities_to_update = Vulnerability.id_in(vulnerabilities_to_resolve.map(&:vulnerability_id))
        vulnerabilities_to_update.update_all(
          state: :resolved,
          auto_resolved: true,
          resolved_by_id: user.id,
          resolved_at: now,
          updated_at: now
        )

        Vulnerability.current_transaction.after_commit do
          Vulnerabilities::BulkEsOperationService.new(vulnerabilities_to_update).execute
          trigger_webhook_events(vulnerabilities_to_update)
        end

        Vulnerabilities::Reads::UpsertService.new(vulnerabilities_to_update,
          { state: :resolved, auto_resolved: true },
          projects: project
        ).execute
      end
    end

    def internal_event_name
      'autoresolve_vulnerability_in_project_after_pipeline_run_if_policy_is_set'
    end

    def track_policy_evaluation
      track_internal_event(
        'evaluate_vulnerability_management_policy_in_project',
        project: project,
        additional_properties: { label: 'auto_resolve' }
      )
    end

    def target_state
      :resolved
    end

    def formatted_system_note(vulnerability, rules_by_vulnerability)
      ::SystemNotes::VulnerabilitiesService.formatted_note(
        transition: 'changed',
        to_value: :resolved,
        reason: nil,
        comment: comment(vulnerability, rules_by_vulnerability)
      )
    end

    def note_metadata_action
      'vulnerability_resolved'
    end

    def comment(vulnerability, rules_by_vulnerability)
      rule = rules_by_vulnerability[vulnerability]
      format(
        _("Auto-resolved by the vulnerability management policy named '%{policy_name}' " \
          "as the vulnerability was no longer detected in pipeline %{pipeline_link}."),
        policy_name: rule.security_policy.name,
        pipeline_link: pipeline_link
      )
    end

    def base_error_message
      "Could not resolve vulnerabilities"
    end
  end
end
