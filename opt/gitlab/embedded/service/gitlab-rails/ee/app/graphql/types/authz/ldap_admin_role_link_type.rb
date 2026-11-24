# frozen_string_literal: true

module Types
  module Authz
    # rubocop: disable Graphql/AuthorizeTypes -- authorizes in resolver
    class LdapAdminRoleLinkType < BaseObject
      graphql_name 'LdapAdminRoleLink'
      description 'Represents an instance-level LDAP link.'

      authorize_granular_token permissions: :read_ldap_admin_role_link, boundary: :instance, boundary_type: :instance,
        assignable_when: [:admin]

      field :id, GraphQL::Types::ID,
        null: false, description: 'ID of the LDAP link.'

      field :created_at, Types::TimeType,
        null: false, description: 'Timestamp of when the role link was created.'

      field :admin_member_role, ::Types::Members::AdminMemberRoleType,
        null: false, description: 'Custom admin member role.', method: :member_role

      field :provider, ::Types::Authz::LdapProviderType,
        null: false, description: 'LDAP provider for the LDAP link.'

      field :cn, GraphQL::Types::String,
        null: true, description: 'Common Name (CN) of the LDAP group.'

      field :filter, GraphQL::Types::String,
        null: true, description: 'Search filter for the LDAP group.'

      # rubocop:disable GraphQL/ExtractType -- sync columns might get removed from this type in future
      # https://gitlab.com/gitlab-org/gitlab/-/issues/534311#note_2491416269
      field :sync_status, Types::Authz::LdapAdminRoleSyncStatusEnum,
        null: true, description: 'Status of the last sync.'

      field :sync_started_at, Types::TimeType,
        null: true, description: 'Timestamp of when the last sync started.'

      field :sync_ended_at, Types::TimeType,
        null: true, description: 'Timestamp of when the last sync ended.'

      field :last_successful_sync_at, Types::TimeType,
        null: true, description: 'Timestamp of the last successful sync.'

      field :sync_error, GraphQL::Types::String,
        null: true, description: 'Error message if the sync has failed.'
      # rubocop:enable GraphQL/ExtractType
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
