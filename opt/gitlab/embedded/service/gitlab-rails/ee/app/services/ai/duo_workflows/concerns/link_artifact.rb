# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module Concerns
      # Provides a best-effort helper for linking a GitLab artifact (work item,
      # merge request, pipeline, note) to a Duo Workflow run.
      #
      # Failure is intentionally non-fatal: the rescue block tracks the exception
      # so it surfaces in error monitoring without ever blocking the caller.
      # Pass the artifact as a block when resolving it can itself raise, since a
      # positional argument is evaluated at the call site, outside the rescue.
      module LinkArtifact
        private

        def link_artifact(workflow, artifact = nil, link_type:, extra_attributes: {})
          return unless workflow

          artifact ||= yield if block_given?
          return unless artifact

          ::Ai::DuoWorkflows::LinkArtifactService.new(
            workflow: workflow,
            artifact: artifact,
            link_type: link_type,
            extra_attributes: extra_attributes
          ).execute
        rescue StandardError => e
          ::Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id)
          nil
        end
      end
    end
  end
end
