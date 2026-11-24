# frozen_string_literal: true

module API
  module Entities
    module Ai
      module DuoWorkflows
        class Workflow < Grape::Entity
          expose :id, documentation: { type: 'Integer' }
          expose :web_url, documentation: { type: 'String', example: 'https://gitlab.example.com/group/project/-/automate/agent-sessions/42' }
          expose :project_id, documentation: { type: 'Integer' }
          expose :namespace_id, documentation: { type: 'Integer' }
          expose :agent_privileges, documentation: { type: 'Integer', is_array: true }
          expose :agent_privileges_names, documentation: { type: 'String', is_array: true }
          expose :pre_approved_agent_privileges, documentation: { type: 'Integer', is_array: true }
          expose :pre_approved_agent_privileges_names, documentation: { type: 'String', is_array: true }
          expose :workflow_definition, documentation: { type: 'String' }
          expose :status_name, as: :status, documentation: { type: 'String' }
          expose :summary, documentation: { type: 'String' }
          expose :title, documentation: { type: 'String' }
          expose :allow_agent_to_request_user, documentation: { type: 'Boolean' }
          expose :image, documentation: { type: 'String' }
          expose :environment, documentation: { type: 'String' }
          expose :ai_catalog_item_version_id, documentation: { type: 'Integer' }

          def agent_privileges_names
            object.agent_privileges.map do |privilege|
              ::Ai::DuoWorkflows::Workflow::AgentPrivileges::ALL_PRIVILEGES[privilege][:name]
            end
          end

          def pre_approved_agent_privileges_names
            object.pre_approved_agent_privileges.map do |privilege|
              ::Ai::DuoWorkflows::Workflow::AgentPrivileges::ALL_PRIVILEGES[privilege][:name]
            end
          end

          expose :workload, documentation: { type: 'Hash' } do |_, opts|
            opts[:workload]
          end

          expose :mcp_enabled?, as: :mcp_enabled, documentation: { type: 'Boolean' }
          expose :incremental_checkpoints_enabled?, as: :incremental_checkpoints_enabled,
            documentation: { type: 'Boolean' }

          expose :gitlab_url, documentation: { type: 'String' } do |_|
            Gitlab.config.gitlab.url
          end
        end
      end
    end
  end
end
