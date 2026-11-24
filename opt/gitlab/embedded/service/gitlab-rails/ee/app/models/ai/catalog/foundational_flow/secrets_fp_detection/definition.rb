# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module SecretsFpDetection
        module Definition
          module_function

          REFERENCE = 'secrets_fp_detection/v1'
          private_constant :REFERENCE

          def configuration
            {
              foundational_flow_reference: REFERENCE,
              display_name: s_(
                "FoundationalFlow|Secret Detection False Positive Detection"
              ),
              description: s_(
                "FoundationalFlow|Analyze critical Secret Detection vulnerabilities."
              ),
              feature_maturity: "ga",
              ai_feature: "secret_vulnerability_fp_detection",
              avatar: "security-flow.png",
              agent_privileges: [
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_FILES,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::RUN_COMMANDS,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::USE_GIT
              ],
              environment: "web",
              triggers: [],
              flow_version: '2.0.0',
              supported_events: [],
              source_branch_resolver: VulnerabilitySourceBranchResolver,
              ultimate_only: true,
              additional_context_resolver: Context,
              context_category_alias: "secret_detection_context"
            }
          end
        end
      end
    end
  end
end
