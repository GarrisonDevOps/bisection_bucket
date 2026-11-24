# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      # Join record between a GitLab Duo Agent Platform session and a merge request.
      # Exposed from both directions: from a session (Workflow#merge_request_links) and
      # from a merge request (MergeRequest#duo_workflow_links). The matching artifact for
      # the caller's direction is the "other" side of the link.
      class WorkflowMergeRequestLinkType < WorkflowLinkBaseType # rubocop: disable Graphql/AuthorizeTypes -- authorization inherited from WorkflowLinkBaseType
        graphql_name 'DuoWorkflowMergeRequestLink'
        description 'Link between a GitLab Duo Agent Platform session and a merge request.'

        field :link_type, Types::Ai::DuoWorkflows::MergeRequestLinkTypeEnum,
          scopes: FIELD_SCOPES,
          null: false, description: 'How the merge request relates to the session.'

        field :merge_request, ::Types::MergeRequestType,
          scopes: FIELD_SCOPES,
          null: true, description: 'Linked merge request.'
      end
    end
  end
end
