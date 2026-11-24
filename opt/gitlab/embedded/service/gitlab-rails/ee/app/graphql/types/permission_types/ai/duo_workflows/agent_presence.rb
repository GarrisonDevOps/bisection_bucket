# frozen_string_literal: true

module Types
  module PermissionTypes
    module Ai
      module DuoWorkflows
        class AgentPresence < BasePermissionType
          graphql_name 'DuoWorkflowAgentPresencePermissions'
          description 'Check permissions for the current user on the session that created the object.'

          authorize_granular_token skip_reason: :parent_authorizes

          abilities :read_duo_workflow
        end
      end
    end
  end
end
