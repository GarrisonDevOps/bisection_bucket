# frozen_string_literal: true

module Ai
  module FlowTriggers
    class UpdateService < BaseService
      UNGATED_UPDATE_PARAMS = %i[
        active
        description
        event_types
        filter
        ready_merge_requests_on_finish
        status_on_finish
        user_id
      ].freeze

      def initialize(project:, current_user:, trigger:)
        @project = project
        @current_user = current_user
        @trigger = trigger
      end

      def execute(params)
        params = params.symbolize_keys

        group_error = group_trigger_error(params)
        return group_error if group_error

        return system_trigger_deactivation_error if deactivating_system_trigger?(params)

        return disallow_new_external_agent_error if disallow_config_path_change?(params)

        change_error = autonomous_change_error(params)
        return change_error if change_error

        config_error = custom_flow_config_error_for_update(params)
        return config_error if config_error

        result = super do |params|
          @trigger.update(params)
          @trigger
        end

        if result.success?
          audit_flow_trigger('flow_trigger_updated', result.payload)
          # Re-materialize Ai::FlowSchedule rows when schedule config in the
          # filter changed, or remove them when the scheduled event type was dropped.
          sync_result = ::Ai::FlowSchedules::SyncFromTriggerService.new(trigger: result.payload).execute

          log_flow_schedule_sync_error(result.payload, sync_result.message) if sync_result.error?
        end

        result
      end

      private

      def existing_state
        {
          autonomous_service_account_id: @trigger.autonomous_service_account_id,
          event_types: @trigger.event_types,
          description: @trigger.description
        }
      end

      def deactivating_system_trigger?(params)
        return false unless params.key?(:active) && !::Gitlab::Utils.to_boolean(params[:active])

        @trigger.event_types.intersect?(::Ai::FlowTrigger::SYSTEM_EVENT_TYPE_IDS)
      end

      def system_trigger_deactivation_error
        ServiceResponse.error(
          message: s_('AICatalog|Security policy triggers cannot be deactivated. ' \
            'Exclude the project in the security policy instead.'),
          reason: ERROR_REASON_INVALID_TRIGGER
        )
      end

      # Runs before BaseService provisions a dedicated service account, which needs a project.
      # Ai::FlowTrigger also rejects it, but only after that provisioning has run.
      def group_trigger_error(params)
        return unless @trigger.group_id

        event_types = params.key?(:event_types) ? params[:event_types] : @trigger.event_types
        return unless ::Ai::FlowTrigger.includes_autonomous?(event_types)

        ServiceResponse.error(
          message: _('Scheduled automations are not supported for group configurations'),
          reason: ERROR_REASON_INVALID_TRIGGER
        )
      end

      def autonomous_change_error(params)
        gated = gated_param_changes(params)
        return if gated.empty?

        service_account_id = existing_state.fetch(:autonomous_service_account_id)
        unless service_account_id
          return new_service_account_goals_error(params, target_ai_catalog_item_consumer(params))
        end

        return unless autonomous_after_apply?(params)

        # Read both: project_authorizations is worker-refreshed, so a freshly provisioned account can
        # still read as having nothing to inherit, and the membership row misses inherited access.
        access_level = [
          project.member(@trigger.autonomous_service_account)&.access_level,
          project.team.max_member_access(service_account_id)
        ].compact.max.nonzero?

        return unless access_level

        service_account_access_error(access_level, gated)
      end

      def gated_param_changes(params)
        gated = params.keys - UNGATED_UPDATE_PARAMS

        gated.select { |name| !@trigger.has_attribute?(name) || changes_attribute?(name, params[name]) }.sort
      end

      def changes_attribute?(name, value)
        value = ::Ai::FlowTrigger.normalize_goals(value) if name == :goals

        @trigger.class.type_for_attribute(name).cast(value) != @trigger[name]
      end

      # Prevent an AI Catalog trigger from becoming a "manual" External Agent trigger
      # unless the user is allowed to create new External Agents.
      # See https://gitlab.com/gitlab-org/gitlab/-/issues/583687.
      def disallow_config_path_change?(params)
        @trigger.ai_catalog_item_consumer_id.present? && params[:config_path].present? && !new_external_agents_allowed?
      end

      # Validates the custom flow config only when the update adds event types to, or repoints the
      # trigger at, a custom flow. Returns a ServiceResponse.error to reject the update, otherwise nil.
      def custom_flow_config_error_for_update(params)
        consumer = target_ai_catalog_item_consumer(params)

        return unless consumer
        return unless adding_event_types?(params) || consumer != @trigger.ai_catalog_item_consumer

        custom_flow_config_error(consumer)
      end

      # The consumer the trigger will point at after the update: the incoming one when
      # ai_catalog_item_consumer_id is supplied, otherwise the trigger's current consumer.
      def target_ai_catalog_item_consumer(params)
        if params.key?(:ai_catalog_item_consumer_id)
          ai_catalog_item_consumer(params[:ai_catalog_item_consumer_id])
        else
          @trigger&.ai_catalog_item_consumer
        end
      end

      def adding_event_types?(params)
        return false unless params.key?(:event_types)

        (Array(params[:event_types]) - Array(@trigger.event_types)).present?
      end
    end
  end
end
