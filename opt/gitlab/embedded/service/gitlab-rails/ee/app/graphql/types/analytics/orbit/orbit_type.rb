# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class OrbitType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- each field authorizes
        graphql_name 'Orbit'
        description 'Orbit data of the instance and of the groups of the current user.'

        authorize_granular_token skip_reason: :child_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :access,
          null: true,
          description: 'Orbit access state of the instance on GitLab Self-Managed and GitLab Dedicated. ' \
            'Null on GitLab.com, where access is per top-level group, and for users who are not administrators.',
          experiment: { milestone: '19.4' },
          resolver: ::Resolvers::Analytics::Orbit::InstanceAccessResolver

        field :excluded_groups,
          null: true,
          description: 'Top-level groups excluded from automatic Orbit indexing. Administrators only. ' \
            'Returns an error for other users.',
          resolver: ::Resolvers::Analytics::Orbit::ExcludedGroupsResolver

        field :groups,
          null: true,
          description: 'Groups visible to the current user. Same arguments as `Query.groups`, plus `enabled`.',
          resolver: ::Resolvers::Analytics::Orbit::GroupsResolver

        field :member_groups,
          null: true,
          description: 'The highest group of each group tree where the current user has at least the Reporter ' \
            'role. With `enabled: true`, only the groups that Orbit answers for.',
          resolver: ::Resolvers::Analytics::Orbit::MemberGroupsResolver

        field :query_templates,
          null: true,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Named queries that Orbit defines, rendered for the current user. ' \
            'Returns null when the user cannot use Orbit. ' \
            'This field can be resolved only once in any single request.',
          experiment: { milestone: '19.4' },
          resolver: ::Resolvers::Analytics::Orbit::QueryTemplatesResolver

        field :schema,
          null: true,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Node kinds and edge kinds that the current user can query in Orbit. ' \
            'Returns null when the user cannot use Orbit or Orbit returns no schema. ' \
            'This field can be resolved only once in any single request.',
          experiment: { milestone: '19.4' },
          resolver: ::Resolvers::Analytics::Orbit::SchemaResolver

        field :service_status,
          null: true,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Health of the Orbit service. ' \
            'Returns null when Orbit is not available on the instance or for the user. ' \
            'This field can be resolved only once in any single request.',
          experiment: { milestone: '19.4' },
          resolver: ::Resolvers::Analytics::Orbit::ServiceStatusResolver
      end
    end
  end
end
