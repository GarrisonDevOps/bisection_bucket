# frozen_string_literal: true

module EE
  module Ci
    module CreateDownstreamPipelineService
      extend ::Gitlab::Utils::Override

      override :log_audit_event
      def log_audit_event(downstream_pipeline)
        return unless downstream_pipeline&.persisted?
        return if downstream_pipeline.parent_pipeline?

        root_pipeline = downstream_pipeline.upstream_root

        audit_context = {
          name: "multi_project_downstream_pipeline_created",
          author: current_user,
          scope: downstream_pipeline.project,
          target: downstream_pipeline,
          target_details: downstream_pipeline.id.to_s,
          message: "Multi-project downstream pipeline created.",
          additional_details: {
            upstream_root_pipeline_id: root_pipeline.id,
            upstream_root_project_path: root_pipeline.project&.full_path
          }
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      private

      # Policy trigger jobs get one level on top of the project's nesting budget,
      # so a policy job injected into the deepest project pipeline can still run.
      override :max_nested_children
      def max_nested_children
        return super + 1 if bridge.source == 'pipeline_execution_policy'

        super
      end
    end
  end
end
