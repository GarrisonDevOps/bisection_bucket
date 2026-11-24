# frozen_string_literal: true

module GitlabSubscriptions
  module CachedPlanTier
    FREE = ::GitlabSubscriptions::SystemDefined::Plan::FREE

    CACHE_EXPIRATION = 10.minutes

    # Bounds the expiry stampede. A single hot requester or namespace can be behind
    # hundreds of concurrent requests, and fetch_once takes no lock, so without this
    # every one of them would miss together and run the same query.
    RACE_CONDITION_TTL = 10.seconds

    class << self
      # GitLab.com only: self-managed has no per-namespace subscription rows, so every
      # id resolves to FREE there.
      def for_user_id(user_id)
        return FREE unless user_id

        fetch_tier(user_cache_key(user_id), :user) do
          highest_tier(plan_name_uids_for_user(user_id))
        end
      end

      def for_root_namespace_id(root_namespace_id)
        return FREE unless root_namespace_id

        fetch_tier(namespace_cache_key(root_namespace_id), :namespace) do
          tier_for_uid(hosted_plan_name_uid(root_namespace_id))
        end
      end

      def expire_for_user(user_id)
        key = user_cache_key(user_id)

        ::Gitlab::SafeRequestStore.delete(key)
        Rails.cache.delete(key)
      end

      private

      # The block runs only when both cache layers miss.
      def fetch_tier(key, subject)
        queried = false

        tier = ::Gitlab::Cache.fetch_once(key, expires_in: CACHE_EXPIRATION,
          race_condition_ttl: RACE_CONDITION_TTL) do
          queried = true
          yield
        end

        lookups_counter.increment(subject: subject, result: queried ? :miss : :hit)

        tier
      end

      # Not memoized: the registry is idempotent and hands back the same counter,
      # while a held reference outlives a registry reset and stops being observable.
      def lookups_counter
        ::Gitlab::Metrics.counter(
          :gitlab_plan_tier_lookups_total,
          'Plan tier lookups, by cached subject and whether the database was queried.',
          { subject: nil, result: nil }
        )
      end

      def user_cache_key(user_id)
        "plan_tier:user:#{user_id}"
      end

      def namespace_cache_key(root_namespace_id)
        "plan_tier:namespace:#{root_namespace_id}"
      end

      # Don't remove this FREE default. The query can return zero rows: a user with
      # no memberships and no provisioning data matches nothing, so there is no plan
      # to read. FREE is the fallback for that case.
      def highest_tier(plan_name_uids)
        names = ::GitlabSubscriptions::SystemDefined::Plan.names_for_uids(plan_name_uids.compact)

        names
          .map { |name| ::GitlabSubscriptions::SystemDefined::Plan.tier_for(name) }
          .max_by { |tier| ::GitlabSubscriptions::SystemDefined::Plan::TIERS.index(tier) } || FREE
      end

      # A namespace with no subscription row, or one carrying no plan name uid, has
      # no plan to read.
      def tier_for_uid(plan_name_uid)
        name = ::GitlabSubscriptions::SystemDefined::Plan.names_for_uids([plan_name_uid].compact).first
        return FREE unless name

        ::GitlabSubscriptions::SystemDefined::Plan.tier_for(name)
      end

      # One DB round trip; unique index on namespace_id, nil if no subscription row
      def hosted_plan_name_uid(root_namespace_id)
        ::GitlabSubscription.where(namespace_id: root_namespace_id).pick(:hosted_plan_name_uid)
      end

      # Shares can only raise the tier, so they are skipped once a direct root is already Ultimate.
      def plan_name_uids_for_user(user_id)
        uids = plan_name_uids_in(::Namespace.from("(#{candidate_root_ids(user_id)}) #{::Namespace.table_name}"))
        return uids if highest_tier(uids) == ::Plan::ULTIMATE

        (uids + shared_plan_name_uids(user_id)).uniq
      end

      # Single round trip; returns up to 12 distinct plan uids
      def plan_name_uids_in(candidates)
        ::GitlabSubscription
          .where(namespace_id: candidates.select(:id))
          .where.not(hosted_plan_name_uid: nil)
          .distinct
          .limit(::GitlabSubscriptions::SystemDefined::Plan::ITEMS.size)
          .pluck(:hosted_plan_name_uid)
      end

      # No query executes; returns SQL text embedded as subquery, UNION ALL (no dedup)
      def candidate_root_ids(user_id)
        ::Gitlab::SQL::Union.new([
          ::Member.without_invites_and_requests.where(user_id: user_id)
                  .joins(:member_namespace).select(root_id_column),
          ::Namespace.where(id: provisioned_group_id(user_id)).select(root_id_column),
          ::Namespace.where(id: provisioned_project_namespace_id(user_id)).select(root_id_column)
        ], remove_duplicates: false).to_sql
      end

      def shared_plan_name_uids(user_id)
        memberships = ::Gitlab::SQL::CTE.new(:direct_memberships,
          ::Member.without_invites_and_requests.where(user_id: user_id).select(:member_namespace_id))
        shared_groups = ::Gitlab::SQL::CTE.new(:shared_groups, shared_group_ids(ids_from(memberships)))
        accessible_groups = ::Gitlab::SQL::CTE.new(:accessible_groups,
          accessible_groups(ids_from(memberships), ids_from(shared_groups)))
        top_groups = ::Gitlab::SQL::CTE.new(:top_groups, top_groups(accessible_groups))

        shared_root_ids = ::Gitlab::SQL::Union.new([
          ::Namespace.where(id: ids_from(shared_groups)).select(root_id_column),
          ::Namespace.where(id: shared_project_namespace_ids(top_groups)).select(root_id_column)
        ], remove_duplicates: false)

        plan_name_uids_in(::Namespace
          .with(memberships.to_arel, shared_groups.to_arel, accessible_groups.to_arel, top_groups.to_arel)
          .from("(#{shared_root_ids.to_sql}) #{::Namespace.table_name}"))
      end

      def ids_from(cte)
        ::Namespace.unscoped.from(cte.table).select(Arel.star)
      end

      # A group share grants access to the invited group's direct members only, as in User#authorized_groups.
      # Project namespace ids among the memberships never match shared_with_group_id, so no type filter is needed.
      def shared_group_ids(member_namespace_ids)
        ::GroupGroupLink
          .not_expired
          .with_at_least_group_access(::Gitlab::Access::GUEST)
          .where(shared_with_group_id: member_namespace_ids)
          .select(:shared_group_id)
      end

      def accessible_groups(member_namespace_ids, shared_group_ids)
        group_ids = ::Gitlab::SQL::Union.new([member_namespace_ids, shared_group_ids], remove_duplicates: false)

        ::Group.where(::Group.arel_table[:id].in(Arel.sql(group_ids.to_sql))).select(:id, :traversal_ids)
      end

      # A nested group would expand its subtree a second time under its ancestor, so only the topmost are kept.
      def top_groups(accessible_groups)
        table = accessible_groups.table.name

        ::Namespace.unscoped.from(accessible_groups.table).select(Arel.star).where(<<~SQL.squish)
          #{table}.id NOT IN (
            SELECT covered.id FROM #{table} covered,
              unnest(covered.traversal_ids[1:cardinality(covered.traversal_ids) - 1]) AS ancestors(id)
            WHERE ancestors.id IN (SELECT id FROM #{table})
          )
        SQL
      end

      # A project share reaches members of the invited group's ancestors and of groups shared with them, as in
      # Gitlab::ProjectAuthorizations. project_authorizations would list every project under the user's groups.
      def shared_project_namespace_ids(top_groups)
        ::Project
          .joins(:namespace)
          .where(namespaces: { share_with_group_lock: false })
          .where(id: shared_project_ids(top_groups))
          .select(:namespace_id)
      end

      # ANY(ARRAY(...)) fences the planner: as IN it misestimates the groups and seq scans project_group_links.
      def shared_project_ids(top_groups)
        ::ProjectGroupLink
          .not_expired
          .where("#{::ProjectGroupLink.table_name}.group_id = " \
            "ANY(ARRAY(#{self_and_descendant_group_ids(top_groups).to_sql}))")
          .select(:project_id)
      end

      # Range join instead of Group.self_and_descendants, whose base dedup is quadratic in the number of groups.
      def self_and_descendant_group_ids(top_groups)
        table = top_groups.table.name

        ::Group
          .joins("INNER JOIN #{table} ON namespaces.traversal_ids >= #{table}.traversal_ids " \
            "AND namespaces.traversal_ids < next_traversal_ids_sibling(#{table}.traversal_ids)")
          .select(:id)
      end

      def root_id_column
        Arel.sql("#{::Namespace.table_name}.traversal_ids[1] AS id")
      end

      # Group id is already a namespace id; may be a subgroup, hence caller's root fold
      def provisioned_group_id(user_id)
        ::UserDetail.where(user_id: user_id).select(:provisioned_by_group_id)
      end

      # Translates project id to projects.namespace_id, which caller folds to root
      def provisioned_project_namespace_id(user_id)
        ::UserDetail
          .where(user_id: user_id)
          .joins(:provisioned_by_project)
          .select("#{::Project.table_name}.namespace_id")
      end
    end
  end
end
