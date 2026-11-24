# frozen_string_literal: true

module Security
  class SyncPolicyWorker
    include Gitlab::EventStore::Subscriber
    include Security::PolicyConfigurationLevelSync

    data_consistency :sticky

    deduplicate :until_executing, including_scheduled: true
    idempotent!

    concurrency_limit -> { 300 }

    feature_category :security_policy_management

    BATCH_DELAY_INTERVAL = 1.second
    BATCH_SIZE = 100

    def handle_event(event)
      security_policy_id = event.data[:security_policy_id]
      policy = Security::Policy.find_by_id(security_policy_id) || return

      case event
      when Security::PolicyCreatedEvent
        handle_create_event(policy, event.data)
      when Security::PolicyUpdatedEvent
        handle_update_event(policy, event.data)
      when Security::PolicyDeletedEvent
        ::Security::DeleteSecurityPolicyWorker.perform_async(security_policy_id)
      when Security::PolicyResyncEvent
        handle_resync_event(policy, event)
      end
    end

    private

    def handle_create_event(policy, event_data)
      return unless policy.enabled

      sync_pipeline_execution_policy_metadata(policy)
      sync_compliance_frameworks(policy)
      # Projects of a newly assigned configuration are synced in bulk by SyncPolicyConfigurationWorker.
      sync_policy_for_projects(policy) unless event_data[:triggered_by_assign]
    end

    def handle_resync_event(policy, event)
      return unless policy.enabled

      sync_pipeline_execution_policy_metadata(policy)
      sync_compliance_frameworks(policy)
      sync_policy_for_projects(policy, {}, event)
    end

    def handle_update_event(policy, event_data)
      policy_diff = Security::SecurityOrchestrationPolicies::PolicyDiff::Diff.from_json(
        event_data[:diff], event_data[:rules_diff]
      )

      sync_pipeline_execution_policy_metadata(policy) if policy_diff.content_changed?
      sync_compliance_frameworks(policy, policy_diff) if policy_diff.scope_changed?

      return unless policy_diff.needs_refresh? || policy_diff.needs_rules_refresh? ||
        reindexed_policy_needs_sync?(policy, policy_diff)

      sync_policy_for_projects(policy, event_data, only_project_ids: listed_project_ids(policy, policy_diff))
    end

    # Scan result policy reads and approval rules store the policy index per project
    def reindexed_policy_needs_sync?(policy, policy_diff)
      policy_diff.policy_index_changed? && policy.type_approval_policy?
    end

    # Unless match_mode is any, a project list scope applies only to the listed projects. Sync the
    # old list (to unlink removed ones) and the new list; linked projects are added per batch. nil means all projects.
    def listed_project_ids(policy, policy_diff)
      new_ids = scope_project_ids(policy.policy_scope)
      return new_ids unless policy_diff.scope_changed?

      old_scope = policy_diff.diff[:policy_scope].from
      old_ids = scope_project_ids(Security::PolicyScope.new(old_scope&.with_indifferent_access))
      return if old_ids.nil? || new_ids.nil?

      old_ids + new_ids
    end

    def scope_project_ids(policy_scope)
      return if policy_scope.match_mode_any?

      policy_scope.projects[:including].presence&.pluck(:id)
    end

    def sync_policy_for_projects(policy, event_data = {}, event = nil, only_project_ids: nil)
      event_payload = event ? { event: { event_type: event.class.name, data: event.data } } : {}
      config_context = if policy.security_orchestration_policy_configuration.namespace?
                         { namespace: policy.security_orchestration_policy_configuration.namespace }
                       else
                         { project: policy.security_orchestration_policy_configuration.project }
                       end

      batch_index = 0

      policy.security_orchestration_policy_configuration.all_project_ids do |project_ids|
        project_ids = (project_ids & only_project_ids) | policy.linked_project_ids(project_ids) if only_project_ids

        project_ids.each_slice(BATCH_SIZE).with_index do |batch, slice_index|
          delay = [BATCH_DELAY_INTERVAL, (batch_index + slice_index) * BATCH_DELAY_INTERVAL].max

          ::Security::SyncProjectPolicyWorker.bulk_perform_in_with_contexts(delay, batch,
            arguments_proc: ->(project_id) do
              [project_id, policy.id, event_data, event_payload.deep_stringify_keys]
            end,
            context_proc: ->(_) { config_context }
          )
        end

        batch_index += (project_ids.size.to_f / BATCH_SIZE).ceil
      end
    end
  end
end
