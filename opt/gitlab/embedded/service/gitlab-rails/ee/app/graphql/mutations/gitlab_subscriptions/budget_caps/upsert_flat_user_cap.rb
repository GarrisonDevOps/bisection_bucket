# frozen_string_literal: true

module Mutations
  module GitlabSubscriptions
    module BudgetCaps
      class UpsertFlatUserCap < BaseMutation
        graphql_name 'UpsertFlatUserCap'

        authorize_granular_token permissions: :update_subscription_usage_cap,
          boundaries: [
            { boundary_argument: :namespace_path, boundary_type: :group },
            { boundary: :instance, boundary_type: :instance, assignable_when: [:admin] }
          ]

        include ResolvesSubscriptionTarget

        description 'Update the flat per-user budget cap for a subscription.'

        argument :namespace_path, GraphQL::Types::String,
          required: false,
          description: 'Path of the top-level group namespace. ' \
            'Omit for self-managed instance scope.'

        argument :flat_user_cap, GraphQL::Types::Float,
          required: true,
          validates: { numericality: { greater_than_or_equal_to: 0 } },
          description: 'Default per-user budget cap applied to all users.'

        argument :flat_user_cap_enabled, GraphQL::Types::Boolean,
          required: true,
          description: 'Whether the flat per-user budget cap is enabled.'

        argument :organization_id, ::Types::GlobalIDType[::Organizations::Organization],
          required: false,
          prepare: ->(global_id, _ctx) { global_id&.model_id },
          experiment: { milestone: '19.6' },
          description: 'Global ID of the organization.'

        validates mutually_exclusive: [:namespace_path, :organization_id]

        # rubocop:disable GraphQL/ExtractType -- flat structure matches CDot API contract
        field :flat_user_cap, GraphQL::Types::Float,
          null: true,
          description: 'Updated flat per-user budget cap.'

        field :flat_user_cap_enabled, GraphQL::Types::Boolean,
          null: true,
          description: 'Whether the flat per-user budget cap is enabled.'
        # rubocop:enable GraphQL/ExtractType

        def resolve(flat_user_cap:, flat_user_cap_enabled:, namespace_path: nil, organization_id: nil)
          target = resolve_target(namespace_path, organization_id)
          authorize_mutation!(target)
          check_usage_rate_limit!(target.namespace)

          client = build_subscription_usage_client(target)
          result = client.upsert_flat_user_cap(
            flat_user_cap: flat_user_cap,
            flat_user_cap_enabled: flat_user_cap_enabled
          )

          if result[:success]
            cap = result[:subscriptionBudgetCap]
            {
              flat_user_cap: cap[:flatUserCap],
              flat_user_cap_enabled: cap[:flatUserCapEnabled],
              errors: []
            }
          else
            {
              flat_user_cap: nil,
              flat_user_cap_enabled: nil,
              errors: result[:errors]
            }
          end
        end
      end
    end
  end
end
