# frozen_string_literal: true

module Mutations
  module IncidentManagement
    module EscalationPolicy
      class Destroy < Base
        graphql_name 'EscalationPolicyDestroy'

        authorize :delete_escalation_policy

        authorize_granular_token permissions: :delete_escalation_policy,
          boundary_argument: :id, boundary: :project, boundary_type: :project

        argument :id, Types::GlobalIDType[::IncidentManagement::EscalationPolicy],
          required: true,
          description: 'Escalation policy internal ID to remove.'

        def resolve(id:)
          escalation_policy = authorized_find!(id: id)

          response ::IncidentManagement::EscalationPolicies::DestroyService.new(
            escalation_policy,
            current_user
          ).execute
        end
      end
    end
  end
end
