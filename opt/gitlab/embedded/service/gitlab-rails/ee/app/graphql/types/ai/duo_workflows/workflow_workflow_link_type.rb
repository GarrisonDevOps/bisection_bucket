# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class WorkflowWorkflowLinkType < WorkflowLinkBaseType # rubocop: disable Graphql/AuthorizeTypes -- authorization inherited from WorkflowLinkBaseType
        graphql_name 'DuoWorkflowWorkflowLink'
        description 'Link between a GitLab Duo Agent Platform session and another session.'

        field :link_type, Types::Ai::DuoWorkflows::WorkflowWorkflowLinkTypeEnum,
          scopes: FIELD_SCOPES,
          null: false, description: 'How the linked session relates to the session.'

        field :linked_workflow, Types::Ai::DuoWorkflows::WorkflowType,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Session the link points to. For a `SOURCE` link, the session that was restarted.'
      end
    end
  end
end
