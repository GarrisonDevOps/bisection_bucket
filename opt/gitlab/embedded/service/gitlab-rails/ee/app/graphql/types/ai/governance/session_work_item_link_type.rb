# frozen_string_literal: true

module Types
  module Ai
    module Governance
      class SessionWorkItemLinkType < SessionLinkBaseType # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes :read_agent_artifacts
        graphql_name 'AiGovernanceSessionWorkItemLink'
        description 'Link between an AI governance session and a work item.'

        PRELOADS = [
          :author, :namespace, { project: [:project_feature, :route, { namespace: :route }] }
        ].freeze

        field :link_type, ::Types::Ai::DuoWorkflows::WorkItemLinkTypeEnum,
          null: false,
          description: 'How the work item relates to the session.'

        field :work_item, ::Types::WorkItemType,
          null: true,
          description: 'Linked work item. Null when the current user cannot read the work item.'

        def work_item
          ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::WorkItem, object.work_item_id, PRELOADS).find
        end
      end
    end
  end
end
