# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class WorkflowPipeline < ::ApplicationRecord
      include WorkflowLinkable

      self.table_name = :duo_workflows_workflow_pipelines

      # pipeline_id references p_ci_pipelines (gitlab_ci database), so the association
      # cannot be joined across databases; integrity is maintained via a loose foreign
      # key (see config/gitlab_loose_foreign_keys.yml).
      links_workflow_to :pipeline, class_name: 'Ci::Pipeline', inverse_of: false

      enum :link_type, {
        # the pipeline the flow was initiated against, e.g. a fix_pipeline flow
        # started from a failed pipeline.
        source: 0
      }, prefix: true

      scope :for_pipelines, ->(pipeline_ids) { where(pipeline_id: pipeline_ids) }
    end
  end
end
