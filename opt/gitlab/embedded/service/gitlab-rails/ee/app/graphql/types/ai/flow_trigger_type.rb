# frozen_string_literal: true

module Types
  module Ai
    class FlowTriggerType < BaseObject
      graphql_name 'AiFlowTriggerType'
      description 'Represents an AI flow trigger'

      connection_type_class Types::Ai::FlowTriggerConnectionType

      authorize :read_ai_flow_triggers

      field :id, GraphQL::Types::ID,
        null: false,
        description: 'ID of the flow trigger.'

      field :active, GraphQL::Types::Boolean,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Indicates whether the flow trigger is active. Inactive triggers do not run automatically.'

      field :description, GraphQL::Types::String,
        null: false,
        description: 'Description of the flow trigger.'

      field :event_types, [GraphQL::Types::Int],
        null: false,
        description: 'List of events that triggers the flow.'

      # rubocop:disable GraphQL/ExtractType -- not for now
      field :config_path, GraphQL::Types::String,
        null: true,
        description: 'Path to the configuration file for the trigger.'

      field :config_url, GraphQL::Types::String,
        null: true,
        description: 'Web URL to the configuration file for the trigger.',
        calls_gitaly: true
      # rubocop:enable GraphQL/ExtractType

      field :ai_catalog_item_consumer, Types::Ai::Catalog::ItemConsumerType,
        null: true,
        description: 'AI catalog item consumer associated with the trigger.'

      field :group, ::Types::GroupType,
        null: true,
        experiment: { milestone: '19.6' },
        description: 'Group of the flow trigger. Null for project flow triggers.'

      field :project, ::Types::ProjectType,
        null: true,
        description: 'Project of the flow trigger. Null for group flow triggers.'

      field :user, ::Types::UserType,
        null: true,
        method: :service_account,
        description: 'Service account of the flow trigger.'

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the flow trigger was created.'

      field :updated_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the flow trigger was last updated.'

      field :filter, GraphQL::Types::JSON, # rubocop:disable Graphql/JSONType -- filter schema is not model backend
        null: true,
        experiment: { milestone: '18.11' },
        description: 'Filter conditions for the AI flow trigger.'

      field :precondition, GraphQL::Types::JSON, # rubocop:disable Graphql/JSONType -- precondition uses same schema as filter
        null: true,
        experiment: { milestone: '18.11' },
        method: :foundational_flow_precondition,
        description: 'Enforced filter conditions from the foundational flow definition.'

      field :status_on_finish, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.6' },
        description: 'Name of the work item status to set when a session that a work item event of the AI flow ' \
          'trigger started finishes. Applies only when the `dap_software_factory` and ' \
          '`ai_flow_trigger_chaining` feature flags are enabled, and only to work items in a project. ' \
          'Requires the `work_item` event type. The work item filter must match all its rules, and have one ' \
          'top-level `action` rule `in` `["status_changed"]` and one top-level `status.name` rule `in` a list ' \
          'of status names.'

      field :ready_merge_requests_on_finish, GraphQL::Types::Boolean,
        null: false,
        experiment: { milestone: '19.6' },
        method: :ready_merge_requests_on_finish?,
        description: 'Indicates whether merge requests created by a session that a work item event of the AI ' \
          'flow trigger started are marked as ready when the session finishes. Applies only when the ' \
          '`dap_software_factory` and `ai_flow_trigger_chaining` feature flags are enabled, and ' \
          'only to work items in a project. ' \
          'Requires the `work_item` event type. The work item filter must match all its rules, and have one ' \
          'top-level `action` rule `in` `["status_changed"]` and one top-level `status.name` rule `in` a list ' \
          'of status names.'

      field :goals, GraphQL::Types::JSON, # rubocop:disable Graphql/JSONType -- keyed by event type, not model backed
        null: false,
        experiment: { milestone: '19.5' },
        description: 'Goals for the AI flow trigger, keyed by event type.'

      field :flow_schedules, Types::Ai::FlowScheduleType.connection_type,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Cron-based schedules associated with the flow trigger.'

      field :last_run, Types::Ai::FlowTrigger::LastRunType,
        null: true,
        experiment: { milestone: '19.6' },
        description: 'Details of the most recent run, or null if the flow trigger has never run.'

      field :running_count, GraphQL::Types::Int,
        null: false,
        experiment: { milestone: '19.6' },
        description: 'Number of sessions of the flow trigger that are created or running.'

      field :run_stats, Types::Ai::FlowTrigger::RunStatsType,
        null: true,
        experiment: { milestone: '19.6' },
        description: 'Statistics of the runs of the flow trigger created in the last 30 days.'

      field :sessions,
        experiment: { milestone: '19.6' },
        resolver: ::Resolvers::Ai::FlowTriggers::SessionsResolver,
        description: 'Sessions started by the flow trigger, newest first by default. ' \
          'Returns sessions for only one flow trigger per request.' do
        extension(::Gitlab::Graphql::Limit::FieldCallCount, limit: 1)
      end

      def last_run
        Gitlab::Graphql::Lazy.with_value(run_summary, &:last_run)
      end

      def running_count
        Gitlab::Graphql::Lazy.with_value(run_summary, &:running_count)
      end

      def run_stats
        ::Gitlab::Graphql::Loaders::Ai::FlowTriggerRunStatsLoader.new(object, current_user).find
      end

      def config_url
        return unless object.config_path.present? && object.project.default_branch

        id = File.join(object.project.default_branch, object.config_path)
        ::Gitlab::Routing.url_helpers.project_blob_path(object.project, id)
      end

      def flow_schedules
        ::Gitlab::Graphql::Loaders::Ai::FlowSchedulesLoader.new(context, object)
      end

      def group
        return unless object.group_id

        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Group, object.group_id).find
      end

      private

      def run_summary
        ::Gitlab::Graphql::Loaders::Ai::FlowTriggerRunSummaryLoader.new(object, current_user).find
      end
    end
  end
end
