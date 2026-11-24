# frozen_string_literal: true

module Types
  module Authz
    # rubocop: disable Graphql/AuthorizeTypes -- ancestor authorization is done in Authz::LdapAdminRoleLinksResolver
    class LdapProviderType < BaseObject
      graphql_name 'LdapProvider'
      description 'Represents a LDAP provider.'

      include Gitlab::Utils::StrongMemoize

      field :label, GraphQL::Types::String,
        description: 'Display name of the LDAP provider.'

      field :id, GraphQL::Types::String,
        description: 'ID of the LDAP provider.'

      def label
        server_labels[object]
      end

      def id
        object
      end

      private

      def server_labels
        ::Gitlab::Auth::Ldap::Config.available_servers.to_h do |server|
          [server.provider_name, server.label]
        end
      end
      strong_memoize_attr :server_labels
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
