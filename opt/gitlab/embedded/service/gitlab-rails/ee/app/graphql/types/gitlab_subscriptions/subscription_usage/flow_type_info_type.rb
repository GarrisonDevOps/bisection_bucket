# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class FlowTypeInfoType < BaseObject
        graphql_name 'GitlabSubscriptionUsageFlowTypeInfo'
        description 'Information about a GitLab Credits flow type.'

        authorize_granular_token parent_authorizes: :read_user

        authorize :read_user

        field :id, GraphQL::Types::String, null: false, # rubocop: disable GraphQL/FieldMethod -- Do not wrap the result with a global ID
          description: 'Identifier for the flow type, used for filtering.'

        field :title, GraphQL::Types::String, null: false,
          description: 'Display name for the flow type.'

        def id
          # BaseObject#id attempts to call `to_global_id` on the underlying object,
          # which fails for Structs. Override to return the plain id string directly.
          object.id
        end
      end
    end
  end
end
