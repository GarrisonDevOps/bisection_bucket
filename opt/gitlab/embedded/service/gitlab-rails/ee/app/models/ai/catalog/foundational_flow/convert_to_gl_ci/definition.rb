# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module ConvertToGlCi
        module Definition
          module_function

          REFERENCE = 'convert_to_gl_ci/v1'
          private_constant :REFERENCE

          def configuration
            {
              foundational_flow_reference: REFERENCE,
              display_name: s_(
                "FoundationalFlow|Convert to GitLab CI/CD"
              ),
              description: s_(
                "FoundationalFlow|Migrate your Jenkins pipelines to GitLab CI/CD."
              ),
              feature_maturity: "ga",
              avatar: "convert-ci-flow.png",
              agent_privileges: [
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_FILES,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_FILES,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::RUN_COMMANDS,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::USE_GIT
              ],
              environment: "web",
              triggers: []
            }
          end
        end
      end
    end
  end
end
