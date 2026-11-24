# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      # Join record between a GitLab Duo Agent Platform session and a pipeline.
      # Exposed from both directions: from a session (Workflow#pipeline_links) and
      # from a pipeline (Ci::Pipeline#duo_workflow_links). The matching artifact for
      # the caller's direction is the "other" side of the link.
      class WorkflowPipelineLinkType < WorkflowLinkBaseType # rubocop: disable Graphql/AuthorizeTypes -- authorization inherited from WorkflowLinkBaseType
        graphql_name 'DuoWorkflowPipelineLink'
        description 'Link between a GitLab Duo Agent Platform session and a pipeline.'

        field :link_type, Types::Ai::DuoWorkflows::PipelineLinkTypeEnum,
          scopes: FIELD_SCOPES,
          null: false, description: 'How the pipeline relates to the session.'

        field :pipeline, ::Types::Ci::PipelineType,
          scopes: FIELD_SCOPES,
          null: true, description: 'Linked pipeline.'
      end
    end
  end
end
