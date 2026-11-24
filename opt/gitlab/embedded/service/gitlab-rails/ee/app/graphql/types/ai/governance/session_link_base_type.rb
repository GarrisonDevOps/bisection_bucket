# frozen_string_literal: true

module Types
  module Ai
    module Governance
      # Shared base for the links between an AI governance session and an artifact. Unlike
      # `Types::Ai::DuoWorkflows::WorkflowLinkBaseType`, it has no `workflow` field, so reading a
      # link doesn't require `:read_duo_workflow`.
      class SessionLinkBaseType < ::Types::BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes :read_agent_artifacts
        graphql_name 'AiGovernanceSessionLinkBase'

        authorize_granular_token skip_reason: :parent_authorizes

        field :id, ::Types::GlobalIDType,
          null: false,
          description: 'Global ID of the link.'

        field :created_at, ::Types::TimeType,
          null: false,
          description: 'Timestamp of when the link was created.'
      end
    end
  end
end
