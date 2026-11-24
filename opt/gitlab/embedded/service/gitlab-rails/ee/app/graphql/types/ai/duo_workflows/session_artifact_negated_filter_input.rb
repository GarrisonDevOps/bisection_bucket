# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class SessionArtifactNegatedFilterInput < ::Types::BaseInputObject
        graphql_name 'DuoWorkflowSessionArtifactNegatedFilterInput'
        description 'Negated filter arguments for Duo Agent Platform session artifacts.'

        argument :workflow_definition, GraphQL::Types::String,
          required: false,
          description: 'Exclude session artifacts with the workflow definition.'

        argument :project_path, GraphQL::Types::String,
          required: false,
          description: 'Exclude session artifacts belonging to the project full path.'

        argument :triggered_by_user_id, ::Types::GlobalIDType[::User],
          required: false,
          description: 'Exclude session artifacts triggered by the user with the given global ID.'
      end
    end
  end
end
