# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Links a Duo Workflow run to a GitLab artifact (work item, merge request, pipeline,
    # note, or another workflow) by creating the matching join record. This is the
    # single entry point for creating those links.
    #
    # GitLab avoids DB-level polymorphism, so each artifact type has its own join model.
    # Register each one in JOIN_MODELS as its model is added; the service dispatches to
    # the right model by matching the artifact against each model's artifact association.
    class LinkArtifactService
      include ::Services::ReturnServiceResponses

      JOIN_MODELS = [
        WorkflowWorkItem,
        WorkflowMergeRequest,
        WorkflowNote,
        WorkflowPipeline,
        WorkflowWorkflow
      ].freeze

      def initialize(workflow:, artifact:, link_type:, extra_attributes: {})
        @workflow = workflow
        @artifact = artifact
        @link_type = link_type
        @extra_attributes = extra_attributes
      end

      def execute
        join_model = join_model_for(@artifact)
        return error("Unsupported artifact type: #{@artifact.class}", :bad_request) unless join_model

        errors = join_model.ensure_link(
          workflow: @workflow, artifact: @artifact, link_type: @link_type, extra_attributes: @extra_attributes)
        return error(errors.full_messages, :unprocessable_entity) if errors.any?

        @artifact.trigger_note_subscription_update if @artifact.is_a?(::Note) && @link_type == :created

        success({})
      end

      private

      def join_model_for(artifact)
        JOIN_MODELS.find do |model|
          association = model.reflect_on_association(model.workflow_artifact_association)
          artifact.is_a?(association.klass)
        end
      end
    end
  end
end
