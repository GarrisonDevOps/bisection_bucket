# frozen_string_literal: true

module EE
  module API
    module Mcp
      module Handlers
        module InitializeRequest
          extend ActiveSupport::Concern
          extend ::Gitlab::Utils::Override

          # Some MCP clients truncate server instructions at 2,048 characters, so keep
          # this text (and any text combined with it later) under that limit.
          DAP_FLOW_INSTRUCTIONS = 'When a GitLab task matches a GitLab Duo flow, for example ' \
            'reviewing a merge request with code_review/v1, fixing a failed pipeline with ' \
            'fix_pipeline/v1, or resolving a SAST vulnerability with resolve_sast_vulnerability/v1, ' \
            'prefer the flow: it runs in CI with the full project context. Call ' \
            'list_duo_agents_and_flows to find it. It uses GitLab credits and can push commits, ' \
            'open merge requests, or post comments as the user. Propose it to the user and confirm ' \
            'before starting, unless the user already asked for it.'

          prepended do
            include ::Mcp::Tools::DuoWorkflows::Availability
          end

          private

          override :server_instructions
          def server_instructions
            return super unless available?(current_user)

            DAP_FLOW_INSTRUCTIONS
          end
        end
      end
    end
  end
end
