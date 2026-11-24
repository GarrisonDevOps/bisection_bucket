# frozen_string_literal: true

# rubocop:disable Graphql/ResolverType -- inherited from Issues::BaseParentResolver
module Resolvers
  class GroupIssuesResolver < Issues::BaseParentResolver
    def self.issuable_collection_name
      'issues'
    end

    include GroupIssuableResolver

    before_connection_authorization do |nodes, current_user|
      projects = nodes.filter_map(&:project)
      ActiveRecord::Associations::Preloader.new(records: projects, associations: project_associations).call
      # Each issue is authorized on its own, so preload what the checks read for the whole page.
      ::Ability.preload_for_batch_checks(current_user, nodes)
    end

    def self.project_associations
      [:namespace, :organization]
    end

    def ready?(**args)
      if args.dig(:not, :release_tag).present?
        raise ::Gitlab::Graphql::Errors::ArgumentError, 'releaseTag filter is not allowed when parent is a group.'
      end

      super
    end
  end
end
# rubocop:enable Graphql/ResolverType

Resolvers::GroupIssuesResolver.prepend_mod
