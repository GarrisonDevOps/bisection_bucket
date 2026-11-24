# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class PipelineLinkTypeEnum < BaseEnum
        graphql_name 'DuoWorkflowPipelineLinkType'
        description 'Type of link between a GitLab Duo Agent Platform session and a pipeline.'

        from_rails_enum(
          ::Ai::DuoWorkflows::WorkflowPipeline.link_types,
          description: 'Link of type `%{name}` between a session and a pipeline.'
        )
      end
    end
  end
end
