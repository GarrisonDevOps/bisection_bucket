# frozen_string_literal: true

module Geo
  module SelectiveSync
    extend ActiveSupport::Concern

    SELECTIVE_SYNC_TYPES = %w[namespaces shards organizations].freeze

    def selective_sync?
      validate_selective_sync_type!

      types = SELECTIVE_SYNC_TYPES

      # If someone enables the FF, tries selective sync by org, and finally disables the FF:
      # 1. We won't raise unknown selective sync type error
      # 2. But we will assume that they want selective sync to be disabled (sync everything).
      types -= ['organizations'] unless ::Gitlab::Geo.geo_selective_sync_by_organizations_enabled?

      types.include?(selective_sync_type)
    end

    def selective_sync_by_namespaces?
      validate_selective_sync_type!

      selective_sync_type == 'namespaces'
    end

    def selective_sync_by_shards?
      validate_selective_sync_type!

      selective_sync_type == 'shards'
    end

    def selective_sync_by_organizations?
      validate_selective_sync_type!
      return false unless ::Gitlab::Geo.geo_selective_sync_by_organizations_enabled?

      selective_sync_type == 'organizations'
    end

    def validate_selective_sync_type!
      return if selective_sync_type.blank?
      return if SELECTIVE_SYNC_TYPES.include?(selective_sync_type)

      raise ::Geo::Errors::UnknownSelectiveSyncType.new(selective_sync_type: selective_sync_type)
    end

    # This method should only be used when:
    #
    # - Selective sync is enabled
    # - A replicable model is associated to Namespace but not to any Project
    #
    # When selectively syncing by namespace: We must sync every replicable of
    # every selected namespace and descendent namespaces.
    #
    # When selectively syncing by shard: We must sync every replicable of every
    # namespace of every project in those shards. We must also sync every ancestor
    # of those namespaces.
    #
    # When selective sync is disabled: This method raises, instead of returning
    # the technically correct `Namespace.all`, because it is easy for it to become
    # part of an unnecessarily complex and inefficient query.
    #
    # @return [ActiveRecord::Relation<Namespace>] returns namespaces based on selective sync settings
    def namespaces_for_group_owned_replicables
      if selective_sync_by_namespaces?
        selected_namespaces_and_descendants
      elsif selective_sync_by_shards?
        selected_leaf_namespaces_and_ancestors
      elsif selective_sync_by_organizations?
        selected_organization_namespaces_and_descendants
      else
        raise ::Geo::Errors::UnknownSelectiveSyncType.new(selective_sync_type: selective_sync_type)
      end
    end

    private

    def selected_organization_namespaces_and_descendants
      read_only_relation(
        Namespace.where(
          organization_id: geo_node_organization_links.select(geo_node_organization_links.arel_table[:organization_id])
        )
      )
    end

    def selected_namespaces_and_descendants
      read_only_relation(
        selected_namespaces_and_descendants_cte.apply_to(Namespace.all)
      )
    end

    def selected_namespaces_and_descendants_cte
      namespaces_table = Namespace.arel_table

      cte = Gitlab::SQL::RecursiveCTE.new(:base_and_descendants)

      cte << geo_node_namespace_links
        .select(geo_node_namespace_links.arel_table[:namespace_id].as('id'))
        .except(:order)

      # Recursively get all the descendants of the base set.
      cte << Namespace
        .select(namespaces_table[:id])
        .from([namespaces_table, cte.table])
        .where(namespaces_table[:parent_id].eq(cte.table[:id]))
        .except(:order)

      cte
    end

    def selected_leaf_namespaces_and_ancestors
      read_only_relation(
        selected_leaf_namespaces_and_ancestors_cte.apply_to(Namespace.all)
      )
    end

    # Returns a CTE selecting namespace IDs for selected shards
    #
    # When we need to sync resources that are only associated with namespaces,
    # but the instance is selectively syncing by shard, we must sync every
    # namespace of every project in those shards. We must also sync every
    # ancestor of those namespaces.
    def selected_leaf_namespaces_and_ancestors_cte
      namespaces_table = Namespace.arel_table

      cte = Gitlab::SQL::RecursiveCTE.new(:base_and_ancestors)

      cte << Namespace
        .select(namespaces_table[:id], namespaces_table[:parent_id])
        .id_in(::Project.selective_sync_scope(self).select(:namespace_id))

      # Recursively get all the ancestors of the base set.
      cte << Namespace
        .select(namespaces_table[:id], namespaces_table[:parent_id])
        .from([namespaces_table, cte.table])
        .where(namespaces_table[:id].eq(cte.table[:parent_id]))
        .except(:order)

      cte
    end

    def read_only_relation(relation)
      # relations using a CTE are not safe to use with update_all as it will
      # throw away the CTE, hence we mark them as read-only.
      relation.extend(Gitlab::Database::ReadOnlyRelation)
      relation
    end
  end
end
