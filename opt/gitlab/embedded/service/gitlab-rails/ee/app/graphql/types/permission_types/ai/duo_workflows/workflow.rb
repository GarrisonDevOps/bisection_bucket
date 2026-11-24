# frozen_string_literal: true

module Types
  module PermissionTypes
    module Ai
      module DuoWorkflows
        class Workflow < BasePermissionType
          graphql_name 'DuoWorkflowPermissions'
          description 'Check permissions for the current user on a Duo workflow.'

          authorize_granular_token parent_authorizes: :read_duo_workflow

          abilities :read_duo_workflow, :update_duo_workflow, :delete_duo_workflow, :resume_duo_workflow,
            :restart_duo_workflow
        end
      end
    end
  end
end
