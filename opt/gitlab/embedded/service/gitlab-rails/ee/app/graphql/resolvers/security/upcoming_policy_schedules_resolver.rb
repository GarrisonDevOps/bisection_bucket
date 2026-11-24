# frozen_string_literal: true

module Resolvers
  module Security
    class UpcomingPolicySchedulesResolver < BaseResolver
      type Types::Security::PipelineExecutionProjectScheduleType.connection_type, null: true
      description 'Find upcoming scheduled runs for a pipeline execution schedule policy.'

      def resolve
        return [] unless object[:type] == ::Security::Policy::PIPELINE_EXECUTION_SCHEDULE_POLICY_TYPE

        ::Gitlab::Graphql::Lazy.with_value(policy_record) do |policy|
          policy ? find_upcoming_schedules(policy) : []
        end
      end

      private

      def policy_record
        config = object[:config]
        policy_index = object[:policy_index]
        return unless config && !policy_index.nil?

        BatchLoader::GraphQL.for([config.id, policy_index]).batch do |keys, loader|
          load_policies_batch(keys, loader)
        end
      end

      def load_policies_batch(keys, loader)
        config_ids = keys.map(&:first).uniq

        policies_by_key = ::Security::Policy
          .for_policy_configuration(config_ids)
          .type_pipeline_execution_schedule_policy
          .undeleted
          .index_by { |p| [p.security_orchestration_policy_configuration_id, p.policy_index] }

        keys.each { |key| loader.call(key, policies_by_key[key]) }
      end

      def find_upcoming_schedules(security_policy)
        ::Security::PipelineExecutionProjectSchedule
          .for_policy(security_policy)
          .preload_project_route
          .preload_security_policy_and_management_project
          .ordered_by_next_run_at
      end
    end
  end
end
