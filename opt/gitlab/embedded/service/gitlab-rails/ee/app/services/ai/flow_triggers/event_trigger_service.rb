# frozen_string_literal: true

module Ai
  module FlowTriggers
    class EventTriggerService
      def initialize(project:, current_user:, event:, data:)
        @project = project
        @current_user = current_user
        @event = event
        @data = data
      end

      def execute
        return unless Ability.allowed?(current_user, :trigger_ai_flow, project)

        flow_triggers = ::Ai::FlowTrigger.applicable_to_project(project, triggered_on: event)
        return unless flow_triggers.any?

        resource = pipeline_from_hook_data if event == ::Ci::Pipelines::HookService::HOOK_NAME
        flow_triggers.each do |flow_trigger|
          filter_evaluator = ::Ai::FlowTriggers::FilterEvaluator.new(
            flow_trigger: flow_trigger, hook_scope: event, data: data
          )

          next unless filter_evaluator.allowed?
          next unless fix_pipeline_trigger_enabled?(flow_trigger, resource)

          ::Ai::FlowTriggers::RunService.new(
            project: project,
            current_user: current_user,
            flow_trigger: flow_trigger,
            resource: resource
          ).execute({ input: data.to_json, event: event })
        end
      end

      private

      attr_reader :project, :current_user, :event, :data

      def pipeline_from_hook_data
        pipeline_id = data.dig(:object_attributes, :id)
        ::Ci::Pipeline.find_by_id(pipeline_id) if pipeline_id
      end

      def fix_pipeline_trigger_enabled?(flow_trigger, pipeline)
        return true unless flow_trigger.foundational_flow&.foundational_flow_reference == 'fix_pipeline/v1'
        return false unless pipeline&.complete?
        return false if merge_request_pipeline_stale?(pipeline)

        # This FF check controls whether for the group we use the gradual rollout.
        return true unless ::Feature.enabled?(:fix_pipeline_gradual_trigger_group, project.root_namespace)

        ::Feature.enabled?(:fix_pipeline_gradual_trigger_gate, :request)
      end

      def merge_request_pipeline_stale?(pipeline)
        return false unless pipeline.merge_request?

        !pipeline.merge_request.diff_head_pipeline?(pipeline)
      end
    end
  end
end
