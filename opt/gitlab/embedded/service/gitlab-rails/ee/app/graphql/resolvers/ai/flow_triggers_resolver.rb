# frozen_string_literal: true

module Resolvers
  module Ai
    class FlowTriggersResolver < BaseResolver
      include LooksAhead

      alias_method :project, :object

      type ::Types::Ai::FlowTriggerType.connection_type, null: true

      authorize :read_ai_flow_triggers

      argument :ids, [::Types::GlobalIDType[::Ai::FlowTrigger]],
        required: false,
        default_value: nil,
        description: 'Filter AI flow triggers by IDs.'

      argument :kind, ::Types::Ai::FlowTrigger::KindEnum,
        required: false,
        experiment: { milestone: '19.6' },
        description: 'Filter AI flow triggers by kind.'

      argument :active, GraphQL::Types::Boolean,
        required: false,
        experiment: { milestone: '19.6' },
        description: 'Filter AI flow triggers by whether they are active.'

      argument :event_type, ::Types::Ai::FlowTrigger::EventTypeEnum,
        required: false,
        experiment: { milestone: '19.6' },
        description: 'Filter AI flow triggers by event type. `MERGE_REQUEST` also matches `MERGE_REQUEST_READY` ' \
          'and `MERGE_REQUEST_CODE_CONFLICT`.'

      argument :search, GraphQL::Types::String,
        required: false,
        validates: { length: { maximum: 255 } },
        experiment: { milestone: '19.6' },
        description: 'Search AI flow triggers by name, config path, or catalog item name. Maximum 255 characters.'

      argument :last_run_status, ::Types::Ai::FlowTrigger::LastRunStatusEnum,
        required: false,
        experiment: { milestone: '19.6' },
        description: 'Filter AI flow triggers by the status of their last run.'

      argument :sort, ::Types::Ai::FlowTrigger::SortEnum,
        required: false,
        default_value: :created_desc,
        experiment: { milestone: '19.6' },
        description: 'Sort AI flow triggers by the criteria.'

      def resolve_with_lookahead(ids: nil, **args)
        workflows = ::Ai::DuoWorkflows::WorkflowsFinder.new(source: project, current_user: current_user).results
        finder = ::Ai::FlowTriggersFinder.new(project, workflows: workflows, ids: ids&.map(&:model_id), **args)

        apply_lookahead(finder.execute)
      end

      private

      def preloads
        {
          user: [
            :user,
            :autonomous_service_account,
            { ai_catalog_item_consumer: [:service_account, { parent_item_consumer: :service_account }] }
          ],
          ai_catalog_item_consumer: { ai_catalog_item_consumer: [:item, :project] },
          precondition: { ai_catalog_item_consumer: :item }
        }
      end
    end
  end
end
