# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Pipeline
        module Chain
          module Populate
            extend ::Gitlab::Utils::Override

            private

            override :force_pipeline_creation_to_continue?
            def force_pipeline_creation_to_continue?
              # If there are security policy pipelines that force pipeline creation,
              # they will be merged onto the pipeline in PipelineExecutionPolicies::ApplyPolicies
              super || command.pipeline_policy_context
                .pipeline_execution_context
                .force_pipeline_creation_on_empty_pipeline?(pipeline)
            end
          end
        end
      end
    end
  end
end
