# frozen_string_literal: true

module Ai
  module FlowTriggers
    class CreateService < BaseService
      def initialize(project:, current_user:, authorization_context: nil)
        unless authorization_context.nil? ||
            authorization_context.is_a?(::Ai::Catalog::Flows::InheritedProjectAuthorization)
          raise ArgumentError, 'Invalid inherited foundational-flow authorization context'
        end

        @project = project
        @current_user = current_user
        @authorization_context = authorization_context
      end

      def execute(params)
        return disallow_new_external_agent_error unless allow_external_agent_trigger?(params)

        consumer = ai_catalog_item_consumer(params[:ai_catalog_item_consumer_id])

        config_error = custom_flow_config_error(consumer)
        return config_error if config_error

        goals_error = new_service_account_goals_error(params, consumer)
        return goals_error if goals_error

        result = super do |params|
          project.ai_flow_triggers.create(params)
        end

        if result.success?
          audit_flow_trigger('flow_trigger_created', result.payload)
          # Schedule config arrives inside the trigger's filter JSON, but execution
          # is driven by Ai::FlowSchedule rows (the dispatcher only scans next_run_at),
          # so the rows must be materialized from the filter or the schedule never fires.
          sync_result = ::Ai::FlowSchedules::SyncFromTriggerService.new(trigger: result.payload).execute

          log_flow_schedule_sync_error(result.payload, sync_result.message) if sync_result.error?
        end

        result
      end

      def allow_external_agent_trigger?(params)
        return true if new_external_agents_allowed?

        params[:config_path].blank?
      end

      private

      # There is no trigger yet, and this service only creates project triggers, so both use the project.
      # Group triggers are created with their inheritance consumer in Ai::Catalog::ItemConsumers::CreateService.
      def permission_subject
        project
      end

      def container
        project
      end
    end
  end
end
