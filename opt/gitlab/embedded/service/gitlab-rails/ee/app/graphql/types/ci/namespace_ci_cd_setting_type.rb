# frozen_string_literal: true

module Types
  module Ci
    class NamespaceCiCdSettingType < BaseObject
      graphql_name 'NamespaceCiCdSetting'

      authorize :read_namespace

      field :allow_stale_runner_pruning, GraphQL::Types::Boolean,
        authorize: :read_runners,
        null: true,
        method: :allow_stale_runner_pruning?,
        description: 'Indicates if stale runners directly belonging to the namespace should be periodically pruned.'

      field :namespace, Types::NamespaceType,
        authorize: :read_namespace,
        null: true, description: 'Namespace the CI/CD settings belong to.'
    end
  end
end
