# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class ProductType < BaseObject
        graphql_name 'GitlabSubscriptionUsageProduct'
        description 'A product with GitLab Credits usage.'

        authorize :read_subscription_usage

        field :id, GraphQL::Types::String, null: false, # rubocop: disable GraphQL/FieldMethod -- Do not wrap the result with a global ID
          description: 'Identifier for the product.'

        field :title, GraphQL::Types::String, null: false,
          description: 'Display name for the product.'

        field :credits_used, GraphQL::Types::Float, null: true,
          description: 'Total GitLab Credits consumed for the product.'

        field :flow_types, [ProductFlowTypeType], null: false,
          description: 'Flow types belonging to the product.'

        def id
          # BaseObject#id attempts to call `to_global_id` on the underlying object,
          # which fails for Structs. Override to return the plain id string directly.
          object.id
        end
      end
    end
  end
end
