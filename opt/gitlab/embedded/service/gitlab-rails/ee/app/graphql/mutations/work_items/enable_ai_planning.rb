# frozen_string_literal: true

module Mutations
  module WorkItems
    class EnableAiPlanning < BaseMutation
      graphql_name 'WorkItemEnableAiPlanning'
      description 'Enables AI planning for a work item. ' \
        'Once enabled, AI planning cannot be disabled.'

      authorize :update_work_item
      authorize_granular_token permissions: :update_work_item,
        boundaries: [
          { boundary_argument: :id, boundary: :resource_parent, boundary_type: :project },
          { boundary_argument: :id, boundary: :resource_parent, boundary_type: :group }
        ]

      argument :id,
        ::Types::GlobalIDType[::WorkItem],
        required: true,
        description: 'Global ID of the work item.'

      field :work_item, ::Types::WorkItemType,
        null: true,
        description: 'Work item after mutation.'

      def resolve(id:)
        work_item = authorized_find!(id: id)

        raise_resource_not_available_error! unless Feature.enabled?(:workplan, work_item.resource_parent&.root_ancestor)
        raise_resource_not_available_error! unless work_item.get_widget(:agent_plan)

        begin
          enable_ai_planning(work_item)
        rescue ActiveRecord::RecordNotUnique
          # A concurrent request created the agent plan; reload so we enable it on that record.
          enable_ai_planning(work_item.reset)
        end
      end

      private

      def enable_ai_planning(work_item)
        agent_plan = work_item.agent_plan || work_item.build_agent_plan
        agent_plan.ai_planning_enabled = true

        if agent_plan.save
          { work_item: work_item.reset, errors: [] }
        else
          { work_item: work_item.reset, errors: errors_on_object(agent_plan) }
        end
      end

      def find_object(id:)
        GitlabSchema.find_by_gid(id)
      end
    end
  end
end
