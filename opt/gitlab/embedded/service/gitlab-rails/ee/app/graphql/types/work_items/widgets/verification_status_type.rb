# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      # rubocop:disable Graphql/AuthorizeTypes -- parent is already authorized
      class VerificationStatusType < BaseObject
        graphql_name 'WorkItemWidgetVerificationStatus'
        description 'Represents a verification status widget'

        authorize_granular_token skip_reason: :parent_authorizes

        implements ::Types::WorkItems::WidgetInterface

        # Only represents requirements status right now
        field :verification_status, GraphQL::Types::String,
          null: true,
          experiment: { milestone: '15.5' },
          description: 'Verification status of the work item.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
