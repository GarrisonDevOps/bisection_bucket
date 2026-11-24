# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Pipeline
        module Chain
          module Skip
            extend ::Gitlab::Utils::Override

            private

            override :skipped?
            def skipped?
              return super unless command.pipeline_policy_context
              return super if command.pipeline_policy_context.skip_ci_allowed?(ref: pipeline.source_ref_path)

              # We don't allow pipeline to be skipped if it has to run execution policies
              # and at least one policy is configured to not allow using skip_ci
              false
            end
          end
        end
      end
    end
  end
end
