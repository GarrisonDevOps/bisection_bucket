# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class WorkflowWorkflowLinkTypeEnum < BaseEnum
        graphql_name 'DuoWorkflowWorkflowLinkType'
        description 'Type of link between two GitLab Duo Agent Platform sessions.'

        from_rails_enum(
          ::Ai::DuoWorkflows::WorkflowWorkflow.link_types,
          description: 'Link of type `%{name}` between a session and another session.'
        )
      end
    end
  end
end
