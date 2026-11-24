# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module SastFpDetection
        module Definition
          module_function

          REFERENCE = 'sast_fp_detection/v1'
          private_constant :REFERENCE

          def configuration
            {
              foundational_flow_reference: REFERENCE,
              display_name: s_(
                "FoundationalFlow|SAST False Positive Detection"
              ),
              description: s_(
                "FoundationalFlow|Analyze critical SAST vulnerabilities."
              ),
              avatar: "security-flow.png",
              feature_maturity: "ga",
              ai_feature: "sast_vulnerability_fp_detection",
              agent_privileges: [
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_FILES,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::RUN_COMMANDS,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::USE_GIT
              ],
              environment: "web",
              triggers: [],
              supported_events: [],
              source_branch_resolver: VulnerabilitySourceBranchResolver,
              flow_version_resolver: ->(container:, user:, additional_context:) do
                [REFERENCE, '1.1.0-dev'] if ::Feature.enabled?(:sast_fp_detection_flow_1_1_0, container.root_ancestor)
              end,
              ultimate_only: true
            }
          end
        end
      end
    end
  end
end
