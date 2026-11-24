# frozen_string_literal: true

module Types
  module Ai
    module Governance
      class SessionNegatedFilterInput < ::Types::BaseInputObject
        graphql_name 'AiGovernanceSessionNegatedFilterInput'
        description 'Negated filter arguments for AI governance sessions.'

        argument :flow_type, GraphQL::Types::String,
          required: false,
          description: 'Exclude sessions with the flow type.'

        argument :project_path, GraphQL::Types::String,
          required: false,
          description: 'Exclude sessions belonging to the project full path.'

        argument :triggered_by_user_id, ::Types::GlobalIDType[::User],
          required: false,
          description: 'Exclude sessions triggered by the user with the given global ID.'
      end
    end
  end
end
