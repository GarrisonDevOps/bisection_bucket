# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class NamespaceType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitNamespace'
        description 'Orbit data of a group or project.'

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :access, AccessType,
          null: true,
          method: :itself,
          authorize: :read_orbit_setting,
          description: 'Orbit access state of the top-level group. Null for subgroups, projects, and when the ' \
            'user cannot read the Orbit setting of the group. ' \
            'This field can be resolved for at most 10 groups in any single request.',
          experiment: { milestone: '19.4' } do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 10
        end

        field :enabled, GraphQL::Types::Boolean,
          null: true,
          description: 'Indicates whether Orbit is turned on for the top-level group of the group. Null for projects.',
          experiment: { milestone: '19.4' }

        field :enabled_at, ::Types::TimeType,
          null: true,
          description: 'Timestamp when Orbit was turned on for the top-level group of the group. Null for projects, ' \
            'when Orbit is off, and when Orbit is not available to the current user.',
          experiment: { milestone: '19.5' }

        field :indexing,
          resolver: ::Resolvers::Analytics::Orbit::IndexingResolver,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Indexing state of the group or project. ' \
            'Null when Orbit is not available to the current user, or when Orbit is off for the top-level group. ' \
            'Null when the user does not have at least the Reporter role in the group or a parent group. ' \
            'Administrators are exempt from the role check. ' \
            'Rate limited to 30 calls per minute for each user. One call covers up to 100 groups or projects. ' \
            '`indexing` and `indexingStatus` share the limit.',
          experiment: { milestone: '19.4' }

        field :indexing_status,
          resolver: ::Resolvers::Analytics::Orbit::IndexingStatusResolver,
          description: 'Indexing status of the group or project. ' \
            'Null when Orbit is not available to the current user, or when Orbit is off for the top-level group. ' \
            'Null when the user does not have at least the Reporter role in the group or a parent group. ' \
            'Administrators are exempt from the role check. ' \
            'Rate limited to 30 calls per minute for each user. One call covers up to 100 groups or projects. ' \
            '`indexing` and `indexingStatus` share the limit.'

        field :item_counts,
          resolver: ::Resolvers::Analytics::Orbit::ItemCountsResolver,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Number of indexed items in the group or project. ' \
            'Null when Orbit is not available to the current user, or when Orbit is off for the top-level group. ' \
            'Null when the user does not have at least the Reporter role in the group or a parent group. ' \
            'Administrators are exempt from the role check. ' \
            'Rate limited to 30 calls per minute for each user. One call covers up to 100 groups or projects. ' \
            'The limit is separate from the `indexing` and `indexingStatus` limit. ' \
            'This field can be resolved for at most 100 groups or projects in any single request.'

        field :trial, TrialType,
          null: true,
          authorize: :read_orbit_trial,
          description: 'Orbit trial of the top-level group, or of the instance on GitLab Self-Managed and GitLab ' \
            'Dedicated. Null for subgroups, projects, when the user cannot ' \
            'read the trial, and when the CustomersDot request fails. ' \
            'This field can be resolved for at most 10 groups in any single request.',
          experiment: { milestone: '19.4' } do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 10
        end

        def enabled
          return unless object.is_a?(::Group)

          ::Gitlab::Graphql::Lazy.with_value(root_enabled_at, &:present?)
        end

        def enabled_at
          return unless object.is_a?(::Group)
          return unless ::Analytics::KnowledgeGraph.status_accessible_for_request?(current_user)

          root_enabled_at
        end

        def trial
          return unless object.is_a?(::Group) && object.root?

          trial = ::Analytics::Orbit::Billing.account_for(object).trial
          return if trial.nil? || trial == :unavailable

          TrialType::Adapter.new(trial: trial, group: object)
        end

        private

        def root_enabled_at
          # Query.groups preloads this association for the orbit field.
          if object.root? && object.association(:knowledge_graph_enabled_namespace).loaded?
            return object.knowledge_graph_enabled_namespace&.created_at
          end

          BatchLoader::GraphQL.for(object.traversal_ids.first).batch do |root_ids, loader|
            ::Analytics::KnowledgeGraph::EnabledNamespace.created_at_by_root_namespace_id(root_ids)
              .each { |root_id, created_at| loader.call(root_id, created_at) }
          end
        end
      end
    end
  end
end
