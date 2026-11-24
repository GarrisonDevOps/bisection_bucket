# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class ProductFlowTypeType < BaseObject
        graphql_name 'GitlabSubscriptionUsageProductFlowType'
        description 'A flow type within a product for GitLab Credits usage.'

        authorize :read_subscription_usage

        field :id, GraphQL::Types::String, null: false, # rubocop: disable GraphQL/FieldMethod -- Do not wrap the result with a global ID
          description: 'Identifier for the flow type.'

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
