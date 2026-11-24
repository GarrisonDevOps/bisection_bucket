# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      # Disabling widget level authorization as it might be too granular
      # and we already authorize the parent work item
      # rubocop:disable Graphql/AuthorizeTypes -- reason above
      class EscalationPolicyType < BaseObject
        graphql_name 'WorkItemWidgetEscalationPolicy'
        description 'Represents the escalation policy widget'

        authorize_granular_token skip_reason: :parent_authorizes

        implements ::Types::WorkItems::WidgetInterface

        field :escalation_policy, ::Types::IncidentManagement::EscalationPolicyType,
          null: true,
          description: 'Escalation policy of the work item.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
