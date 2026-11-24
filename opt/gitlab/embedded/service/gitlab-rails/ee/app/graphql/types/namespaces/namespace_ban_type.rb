# frozen_string_literal: true

module Types
  module Namespaces
    class NamespaceBanType < BaseObject # rubocop:disable Graphql/AuthorizeTypes(Authorization is done in resolver layer)
      graphql_name 'NamespaceBan'

      # Only the NamespaceBanDestroy payload returns this type, and the mutation
      # authorizes the granular token with delete_namespace_ban.
      authorize_granular_token skip_reason: :parent_authorizes

      field :id,
        type: ::Types::GlobalIDType, null: false, description: 'Global ID of the namespace ban.'

      field :namespace, NamespaceType,
        null: false, description: 'Root namespace to which the ban applies.'

      field :user, UserType,
        null: false, description: 'User to which the namespace ban applies.'
    end
  end
end
