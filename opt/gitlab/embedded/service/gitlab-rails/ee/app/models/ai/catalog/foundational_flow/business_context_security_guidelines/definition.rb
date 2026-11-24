# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module BusinessContextSecurityGuidelines
        module Definition
          module_function

          REFERENCE = 'business_context_security_guidelines/experimental'
          private_constant :REFERENCE

          def configuration
            {
              foundational_flow_reference: REFERENCE,
              display_name: s_(
                "FoundationalFlow|Vulnerability Context Flow"
              ),
              description: s_(
                "FoundationalFlow|Analyze project codebase to generate security context for " \
                  "vulnerability prioritization."
              ),
              avatar: "security-flow.png",
              feature_maturity: "experimental",
              feature_flag: "sdlc_context_agent_trigger",
              agent_privileges: [
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_GITLAB
              ],
              environment: "ambient",
              triggers: [],
              supported_events: [],
              ultimate_only: true
            }
          end
        end
      end
    end
  end
end
