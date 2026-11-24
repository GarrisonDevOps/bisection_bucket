# frozen_string_literal: true

module EE
  module Ci
    module DestroyPipelineService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute(pipeline)
        response = super(pipeline)
        log_audit_event(pipeline) if record_destroyed?(pipeline)
        response
      end

      private

      def log_audit_event(pipeline)
        audit_context = {
          name: "destroy_pipeline",
          author: current_user,
          scope: project,
          target: pipeline,
          target_details: pipeline.id.to_s,
          message: "Deleted pipeline in #{pipeline.ref} with status #{pipeline.status} and SHA #{pipeline.sha}"
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def record_destroyed?(pipeline)
        bulk_reload([pipeline]).none?
      end
    end
  end
end
