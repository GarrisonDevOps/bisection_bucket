# frozen_string_literal: true

module Types
  module Ai
    module Governance
      class SessionMergeRequestLinkType < SessionLinkBaseType # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes :read_agent_artifacts
        graphql_name 'AiGovernanceSessionMergeRequestLink'
        description 'Link between an AI governance session and a merge request.'

        PRELOADS = [:author, { target_project: [:project_feature, :route, { namespace: :route }] }].freeze

        field :link_type, ::Types::Ai::DuoWorkflows::MergeRequestLinkTypeEnum,
          null: false,
          description: 'How the merge request relates to the session.'

        field :merge_request, ::Types::MergeRequestType,
          null: true,
          description: 'Linked merge request. Null when the current user cannot read the merge request.'

        def merge_request
          ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::MergeRequest, object.merge_request_id, PRELOADS).find
        end
      end
    end
  end
end
