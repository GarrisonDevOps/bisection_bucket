# frozen_string_literal: true

module EE
  module RepositoryCheck
    module BatchWorker
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      override :perform
      def perform(shard_name)
        # On a true Geo secondary, all data is replicated, so skip all
        # repository checks entirely.
        super unless ::Gitlab::Geo.secondary?
      end

      # rubocop: disable CodeReuse/ActiveRecord -- same pattern as base class
      override :projects_on_shard
      def projects_on_shard
        scope = super

        # On an org migration target cell, only selected organizations'
        # projects are replicas. Exclude those from repository checks so
        # source-of-truth projects still get checked.
        return scope unless ::Gitlab::Geo.org_migration_target?

        node = ::Gitlab::Geo.current_node
        return scope unless node.selective_sync_by_organizations?

        scope.where.not(
          organization_id: node.geo_node_organization_links.select(:organization_id)
        )
      end
      # rubocop: enable CodeReuse/ActiveRecord
    end
  end
end
