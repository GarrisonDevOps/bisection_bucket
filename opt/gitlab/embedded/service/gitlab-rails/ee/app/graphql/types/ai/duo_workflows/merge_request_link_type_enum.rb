# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class MergeRequestLinkTypeEnum < BaseEnum
        graphql_name 'DuoWorkflowMergeRequestLinkType'
        description 'Type of link between a GitLab Duo Agent Platform session and a merge request.'

        from_rails_enum(
          ::Ai::DuoWorkflows::WorkflowMergeRequest.link_types,
          description: 'Link of type `%{name}` between a session and a merge request.'
        )
      end
    end
  end
end
