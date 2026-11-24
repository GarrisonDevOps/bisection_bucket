# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module SlackAssistant
        module Definition
          module_function

          REFERENCE = 'slack_assistant/v1'
          private_constant :REFERENCE

          def configuration
            {
              foundational_flow_reference: REFERENCE,
              display_name: s_(
                "FoundationalFlow|GitLab Duo for Slack"
              ),
              description: s_(
                "FoundationalFlow|Answers questions and takes actions when GitLab Duo is mentioned in Slack."
              ),
              avatar: "gitlab-duo-flow.png",
              feature_maturity: "ga",
              feature_flag: "slack_duo_api_flow",
              requires_enablement: false,
              flow_version: '^1.0.0',
              agent_privileges: [
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::START_FLOWS
              ],
              pre_approved_agent_privileges: [
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB
              ],
              allow_agent_to_request_user: true,
              environment: "ambient",
              coding_environment: "none",
              triggers: [],
              supported_events: []
            }
          end
        end
      end
    end
  end
end
