# frozen_string_literal: true

module Security
  module PipelineExecutionPolicy
    class UsageTracking
      include ::Gitlab::InternalEventsTracking

      MIXED = 'mixed'

      def initialize(project:, policy_pipelines:)
        @project = project
        @policy_pipelines = policy_pipelines
      end

      def track_enforcement
        track('enforce_pipeline_execution_policy_in_project', properties: additional_properties)
      end

      def track_job_execution
        track('execute_job_pipeline_execution_policy')
      end

      private

      attr_reader :project, :policy_pipelines

      def track(event, properties: {})
        track_internal_event(
          event,
          project: project,
          additional_properties: properties)
      end

      def additional_properties
        return {} if policy_pipelines.none?

        strategies = policy_pipelines.map(&:config_strategy).uniq

        {
          label: strategies.size > 1 ? MIXED : strategies.first.to_s,
          property: variables_options,
          value: policy_pipelines.size
        }
      end

      def variables_options
        variables_strategy = policy_pipelines.map(&:variables_override_strategy).uniq
        return 'highest_precedence' if variables_strategy.none?

        if variables_strategy.size > 1
          MIXED
        else
          variables_strategy.first[:allowed] ? 'override_allowed' : 'override_not_allowed'
        end
      end
    end
  end
end
