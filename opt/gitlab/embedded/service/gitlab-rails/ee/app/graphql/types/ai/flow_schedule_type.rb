# frozen_string_literal: true

module Types
  module Ai
    class FlowScheduleType < BaseObject
      graphql_name 'AiFlowScheduleType'
      description 'Represents a cron-based schedule for an AI flow trigger.'

      authorize :read_ai_flow_triggers
      authorize_granular_token skip_reason: :parent_authorizes

      field :id, ::Types::GlobalIDType[::Ai::FlowSchedule],
        null: false,
        description: 'Global ID of the flow schedule.'

      field :description, GraphQL::Types::String,
        null: false,
        description: 'Description of the flow schedule.'

      field :cron, GraphQL::Types::String,
        null: false,
        description: 'Cron expression defining the schedule frequency.'

      field :cron_timezone, GraphQL::Types::String,
        null: false,
        description: 'IANA timezone for the cron expression.'

      field :active, GraphQL::Types::Boolean,
        null: false,
        description: 'Indicates the schedule is active.'

      field :next_run_at, Types::TimeType,
        null: true,
        description: 'Timestamp of the next scheduled execution.'

      field :last_run, Types::Ai::FlowScheduleLastRunType,
        null: true,
        description: 'Details of the most recent execution attempt, or null if the schedule has never run.'

      field :consecutive_failure_count, GraphQL::Types::Int,
        null: false,
        description: 'Number of consecutive execution failures.'

      field :flow_trigger, Types::Ai::FlowTriggerType,
        null: false,
        description: 'Flow trigger the schedule executes.'

      field :project, ::Types::ProjectType,
        null: false,
        description: 'Project of the flow schedule.'

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the flow schedule was created.'

      field :updated_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the flow schedule was last updated.'

      def last_run
        object if object.last_run_at
      end
    end
  end
end
