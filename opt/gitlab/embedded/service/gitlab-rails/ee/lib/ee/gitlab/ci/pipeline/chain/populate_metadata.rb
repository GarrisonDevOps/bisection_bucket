# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Pipeline
        module Chain
          module PopulateMetadata
            extend ::Gitlab::Utils::Override

            override :perform!
            def perform!
              record_security_policy_bypass

              super
            end

            override :set_pipeline_name
            def set_pipeline_name
              policy_pipeline_name = policy_pipeline_metadata[:name]
              return super if policy_pipeline_name.blank?

              assign_to_metadata(name: policy_pipeline_name.strip)
            end

            private

            # Push options are gone once the pipeline exists, so this record is
            # the only durable trace of the bypass. Pipelines persisted before
            # this step ([skip ci], save_incompleted failures) never get the
            # flag, so false means "not recorded", not "definitely not bypassed".
            def record_security_policy_bypass
              return unless command.security_policy_protected_branch_bypassed

              assign_to_metadata(security_policy_protected_branch_bypassed: true)
            end

            def policy_pipeline_metadata
              command.pipeline_policy_context.pipeline_execution_context.overridden_pipeline_metadata
            end
          end
        end
      end
    end
  end
end
