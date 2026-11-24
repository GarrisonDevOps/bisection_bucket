# frozen_string_literal: true

module Types
  module Govern
    # rubocop:disable Graphql/AuthorizeTypes -- Static catalog container; the parent organization, group, or project field gates visibility.
    class PolicyStoreType < BaseObject
      graphql_name 'PolicyStore'
      description 'Catalogs available when creating a policy in the policy store.'

      authorize_granular_token skip_reason: :parent_authorizes

      field :actions, [::Types::Govern::PolicyStoreActionType],
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Actions available when creating a policy in the policy store.'

      field :policies, ::Types::Govern::PolicyType.connection_type,
        null: true,
        authorize: :read_govern_policy,
        resolver: ::Resolvers::Govern::PoliciesResolver,
        connection_extension: Gitlab::Graphql::Extensions::ForwardOnlyExternallyPaginatedArrayExtension,
        max_page_size: ::Gitlab::PolicyStore::Ports::PolicyRepository::MAX_PER_PAGE,
        experiment: { milestone: '19.4' },
        description: 'Policies stored in the policy store for the organization, group, or project. ' \
          "For a group, organization-wide, ancestor, and descendant groups' policies are included. " \
          "For a project, organization-wide policies and its ancestor groups' policies are included. " \
          'Policies are not filtered by their scope. ' \
          'Only `first` and `after` are supported; page with `pageInfo.endCursor`. ' \
          "Cursor offsets are capped at #{::Gitlab::PolicyStore::Ports::PolicyRepository::MAX_OFFSET}, " \
          'so policies past that window cannot be paged. ' \
          'The `ids` argument cannot be combined with pagination arguments. ' \
          'Returns `null` when the current user cannot read the policies of the container.'

      field :policy_evaluations, ::Types::Govern::PolicyEvaluationType.connection_type,
        null: true,
        authorize: :read_govern_policy,
        resolver: ::Resolvers::Govern::PolicyEvaluationsResolver,
        experiment: { milestone: '19.4' },
        description: 'Recorded evaluations of the policies stored in the policy store ' \
          'for the organization, group, or project, newest first. For a group, evaluations of its own ' \
          "and descendant groups' policies are returned, plus evaluations of inherited policies " \
          "recorded against the group's projects. Empty for a project. " \
          'Pages are capped at 50 evaluations, because each evaluation carries an ' \
          'unpaginated list of violations. ' \
          'Returns `null` when the current user cannot read the policies of the container.'

      field :rules, [::Types::Govern::PolicyStoreRuleType],
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Rule kinds available when creating a policy in the policy store.'

      field :triggers, [::Types::Govern::PolicyStoreTriggerType],
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Triggers available when creating a policy in the policy store.'

      def actions
        ::Gitlab::PolicyStore::Actions::ALL
      end

      def rules
        ::Gitlab::PolicyStore::Rules::ALL
      end

      def triggers
        ::Gitlab::PolicyStore::Triggers::ALL
      end
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
