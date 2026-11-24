# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      # Shared base for the join types that link a GitLab Duo Agent Platform
      # session to an artifact (merge request, note, work item). Holds the
      # common authorization, token scopes, and the fields every link exposes
      # (the session side and the timestamp). Each subclass adds only its
      # artifact-specific field and the matching `link_type` enum.
      class WorkflowLinkBaseType < Types::BaseObject
        graphql_name 'DuoWorkflowLinkBase'
        authorize :read_duo_workflow
        authorize_granular_token permissions: :read_duo_workflow, boundary: :user, boundary_type: :user

        FIELD_SCOPES = [:api, :read_api, :ai_features, :ai_workflows].freeze

        field :workflow, Types::Ai::DuoWorkflows::WorkflowType,
          scopes: FIELD_SCOPES,
          null: true, description: 'Linked GitLab Duo Agent Platform session.'

        field :created_at, Types::TimeType,
          scopes: FIELD_SCOPES,
          null: false, description: 'Timestamp of when the link was created.'
      end
    end
  end
end
