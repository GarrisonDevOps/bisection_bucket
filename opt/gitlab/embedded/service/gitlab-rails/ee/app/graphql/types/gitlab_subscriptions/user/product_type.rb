# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module User
      # Similar to SubscriptionUsage::ProductType but authorizes `read_user`
      class ProductType < BaseObject
        graphql_name 'GitlabSubscriptionUserCreditsUsageProduct'
        description 'A product with its flow types.'

        authorize_granular_token skip_reason: :parent_authorizes

        authorize :read_user

        field :id, GraphQL::Types::String, null: false, # rubocop: disable GraphQL/FieldMethod -- Do not wrap the result with a global ID
          description: 'Identifier for the product.'

        field :title, GraphQL::Types::String, null: false,
          description: 'Display name for the product.'

        field :flow_types, [SubscriptionUsage::FlowTypeInfoType], null: false,
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
