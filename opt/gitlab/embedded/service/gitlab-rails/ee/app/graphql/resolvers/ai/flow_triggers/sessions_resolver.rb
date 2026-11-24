# frozen_string_literal: true

module Resolvers
  module Ai
    module FlowTriggers
      class SessionsResolver < BaseResolver
        STATUS_SORTS = %i[status_asc status_desc].freeze

        alias_method :flow_trigger, :object

        type ::Types::Ai::DuoWorkflows::WorkflowType.connection_type, null: true

        argument :statuses, [::Types::Ai::DuoWorkflows::WorkflowStatusEnum],
          required: false,
          experiment: { milestone: '19.6' },
          validates: { length: { maximum: ::Types::BaseArgument::MAX_ARRAY_SIZE } },
          description: 'Exact statuses to filter sessions by. ' \
            "Maximum is #{::Types::BaseArgument::MAX_ARRAY_SIZE} statuses."

        argument :search, GraphQL::Types::String,
          required: false,
          experiment: { milestone: '19.6' },
          description: 'Session goal or ID to search for.'

        argument :created_after, ::Types::TimeType,
          required: false,
          experiment: { milestone: '19.6' },
          description: 'Filters sessions created after the timestamp.'

        argument :created_before, ::Types::TimeType,
          required: false,
          experiment: { milestone: '19.6' },
          description: 'Filters sessions created before the timestamp.'

        argument :sort, ::Types::Ai::DuoWorkflows::WorkflowSortEnum,
          required: false,
          experiment: { milestone: '19.6' },
          description: 'Sort sessions by the criteria. Newest first if not set.'

        before_connection_authorization do |workflows, current_user|
          ::Ai::DuoWorkflows::WorkflowPolicyPreloader.new(workflows, current_user).execute
        end

        def resolve(**args)
          return ::Ai::DuoWorkflows::Workflow.none unless flow_trigger.project

          workflows = ::Ai::DuoWorkflows::WorkflowsFinder.new(
            source: flow_trigger.project,
            current_user: current_user,
            flow_triggers: [flow_trigger],
            statuses: args[:statuses],
            search: args[:search],
            created_after: args[:created_after],
            created_before: args[:created_before],
            sort: args[:sort] || :id_desc
          ).results.with_preloaded_associations

          # Keyset cursors repeat and skip rows under the status sort, as in WorkflowsResolver.
          return offset_pagination(workflows) if args[:sort].in?(STATUS_SORTS)

          workflows
        end
      end
    end
  end
end
