# frozen_string_literal: true

module Types
  module Govern
    # rubocop:disable Graphql/AuthorizeTypes -- Static catalog value object; gating happens in the resolver.
    class PolicyStoreTriggerType < BaseObject
      graphql_name 'PolicyStoreTrigger'
      description 'Trigger available when creating a policy in the policy store.'

      authorize_granular_token skip_reason: :parent_authorizes

      field :id, # rubocop: disable GraphQL/FieldHashKey -- BaseObject#id calls to_global_id on plain hashes; explicit override required
        GraphQL::Types::ID,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Identifier of the trigger.'

      field :name, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Human-readable name of the trigger.'

      field :kind, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.6' },
        description: 'Kind of the trigger. A `gate` trigger is evaluated before the change and can stop it, ' \
          'an `event` trigger is evaluated after the change and cannot.'

      field :available_roles,
        [Types::Govern::PolicyStoreRoleType],
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Roles available for the trigger type.'

      # BaseObject#id builds a GlobalID, which these plain hash catalog entries lack.
      def id
        object[:id]
      end

      def available_roles
        ::Gitlab::PolicyStore::Roles.for_trigger(object[:id])
      end
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
