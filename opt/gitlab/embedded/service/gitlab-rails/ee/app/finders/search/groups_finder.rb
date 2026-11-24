# frozen_string_literal: true

# Finder for retrieving authorized groups to use for search
# This finder returns all groups that a user has authorization to because:
# 1. They are direct members of the group with either:
#   - the minimum access level required
#   - a custom role that allows the ability requested
# 2. They are direct members of a group that is invited to the group with either:
#   - the minimum access level required
#   - a custom role that allows the ability requested
#
# Min access level can be changed by sending `features` option in params. Min access defaults to GUEST
# This finder does not take into account a group's sub-groups, descendants, or ancestors
module Search
  class GroupsFinder
    include Gitlab::Utils::StrongMemoize
    include Search::Concerns::FeatureCustomAbilityMap

    DEFAULT_MIN_ACCESS_LEVEL = ::Gitlab::Access::GUEST
    REDIS_CACHE_TTL = 5.minutes
    CACHE_VERSION_TTL = 1.day
    ACCESS_LEVEL_ROWS_ALIAS = 'authorized_group_accesses'

    def self.cache_version_key(user_id)
      "search_user:#{user_id}:groups_cache_version"
    end

    def self.cache_version(user_id)
      Rails.cache.fetch(cache_version_key(user_id), expires_in: CACHE_VERSION_TTL) { SecureRandom.hex(8) }
    end

    def self.redis_cache_key(user_id, min_access_level:, features: [])
      features_key = Array(features).sort.join(",")
      version = cache_version(user_id)
      "search_user:#{user_id}:v#{version}:min_access_level:#{min_access_level}:features:#{features_key}:groups"
    end

    # Bumping the per-user version orphans every existing key under that user,
    # which covers all min_access_level + features combinations without enumeration.
    def self.expire_cache_for_users(user_ids)
      entries = user_ids.to_h { |user_id| [cache_version_key(user_id), SecureRandom.hex(8)] }
      Rails.cache.write_multi(entries, expires_in: CACHE_VERSION_TTL)
    end

    # user - The currently logged-in user, if any.
    # params
    #  * features (optional, default GUEST) - Sets minimum access level required to access project features.
    #    Cannot be provided with min_access_level
    #  * min_access_level (optional, default GUEST) - Sets minimum access level.
    #    Cannot be provided with features
    def initialize(user:, params: {})
      @user = user
      @params = params
    end

    def execute
      return Group.none unless user

      validate_arguments!

      fetch_with_redis_cache
    end

    # Same authz shape as #execute (Arm 1: direct members, Arm 3: linked via
    # GroupGroupLink), returned as [{organization_id:, traversal_ids:,
    # access_levels:}, ...]. `access_levels` carries the exact effective roles
    # the user holds on that group: direct Member.access_level values for
    # direct paths, or LEAST(GroupGroupLink.group_access, member access on the
    # sharer) for linked paths. Callers that need per-path role information
    # (e.g. the Knowledge Graph JWT publisher) use this instead of #execute
    # followed by a separate members lookup.
    #
    # Arm 2 (custom-role abilities) is intentionally excluded: custom roles
    # grant specific abilities, not a numeric access_level. `features:` is
    # rejected rather than silently dropped.
    def execute_with_access_levels
      return [] unless user

      validate_arguments!
      raise ArgumentError, 'execute_with_access_levels does not support features:' if params[:features].present?

      fetch_access_levels_with_redis_cache
    end

    private

    attr_reader :user, :params

    def fetch_with_redis_cache
      cache_key = self.class.redis_cache_key(user.id, min_access_level: min_access_level, features: params[:features])
      cached_ids = Rails.cache.read(cache_key)

      return Group.unscoped.id_in(cached_ids) if cached_ids

      ids = fetch_groups.pluck_primary_key
      Rails.cache.write(cache_key, ids, expires_in: REDIS_CACHE_TTL)
      Group.unscoped.id_in(ids)
    end

    def fetch_groups
      Group.unscoped do
        Group.from_union([
          direct_groups_with_min_access_level,
          direct_groups_with_custom_role_abilities,
          linked_groups_with_min_access_level
        ].compact)
      end
    end

    def fetch_access_levels_with_redis_cache
      base_key = self.class.redis_cache_key(user.id, min_access_level: min_access_level, features: nil)
      key = "#{base_key}:access_levels"
      cached = normalize_cached_access_level_rows(Rails.cache.read(key))
      return cached if cached

      rows = fetch_access_levels
      Rails.cache.write(key, rows, expires_in: REDIS_CACHE_TTL)
      rows
    end

    # Single UNION ALL over direct + linked, aggregated by (organization_id,
    # traversal_ids) so each path appears once at its highest effective role.
    def fetch_access_levels
      # rubocop:disable CodeReuse/ActiveRecord -- authz union query, no existing scope covers it
      rows = ::Namespace
        .unscoped
        .from_union(access_level_rows, remove_duplicates: false, alias_as: ACCESS_LEVEL_ROWS_ALIAS)
        .joins(access_level_rows_namespace_join)
        .select(
          'namespaces.organization_id',
          'namespaces.traversal_ids',
          access_levels_aggregate_sql
        )
        .group('namespaces.organization_id', 'namespaces.traversal_ids')

      rows.map do |row|
        {
          organization_id: row.organization_id,
          traversal_ids: row.traversal_ids,
          access_levels: row.attributes['access_levels']
        }
      end
      # rubocop:enable CodeReuse/ActiveRecord
    end

    def normalize_cached_access_level_rows(rows)
      return unless rows.is_a?(Array)

      normalized_rows = rows.map do |row|
        next unless row.is_a?(Hash)

        {
          organization_id: row[:organization_id] || row['organization_id'],
          traversal_ids: row[:traversal_ids] || row['traversal_ids'],
          access_levels: row[:access_levels] || row['access_levels']
        }
      end

      return unless normalized_rows.all? do |row|
        row &&
          row[:organization_id].present? &&
          row[:traversal_ids].is_a?(Array) &&
          row[:access_levels].is_a?(Array)
      end

      normalized_rows
    end

    def access_level_rows
      [
        direct_groups_with_access_levels,
        linked_groups_with_access_levels
      ]
    end

    def direct_groups_with_access_levels
      active_group_members
        .with_at_least_access_level(min_access_level)
        .select('members.source_id AS group_id', 'members.access_level AS access_level')
    end

    # rubocop:disable CodeReuse/ActiveRecord -- authz union query, no existing scope covers it
    def linked_groups_with_access_levels
      active_group_members
        .joins('JOIN group_group_links ON members.source_id = group_group_links.shared_with_group_id')
        .merge(GroupGroupLink.not_expired)
        .where("#{linked_group_access_level_sql} >= ?", min_access_level)
        .select('group_group_links.shared_group_id AS group_id', "#{linked_group_access_level_sql} AS access_level")
    end
    # rubocop:enable CodeReuse/ActiveRecord

    def active_group_members
      user.group_members.active.active_state.not_expired
    end

    def linked_group_access_level_sql
      'LEAST(group_group_links.group_access, members.access_level)'
    end

    def access_levels_aggregate_sql
      <<~SQL.squish
        ARRAY_AGG(
          DISTINCT #{ACCESS_LEVEL_ROWS_ALIAS}.access_level
          ORDER BY #{ACCESS_LEVEL_ROWS_ALIAS}.access_level
        )::int[] AS access_levels
      SQL
    end

    def access_level_rows_namespace_join
      <<~SQL.squish
        JOIN namespaces
          ON namespaces.id = #{ACCESS_LEVEL_ROWS_ALIAS}.group_id
         AND namespaces.type = 'Group'
      SQL
    end

    def validate_arguments!
      return unless params[:min_access_level].present? && params[:features].present?

      raise ArgumentError, 'only min_access_level or features can be provided, not both'
    end

    def direct_groups_with_min_access_level
      Group.id_in(direct_groups.with_at_least_access_level(min_access_level).select(:source_id))
    end

    def direct_groups_with_custom_role_abilities
      return Group.none if target_abilities.blank?

      groups = Group.id_in(direct_groups.select(:source_id))
      actual_abilities = ::Authz::Group.new(user, scope: groups).permitted
      allowed_group_ids = groups.filter_map do |group|
        group.id if (actual_abilities[group.id] || []).intersection(target_abilities).any?
      end

      return Group.none if allowed_group_ids.blank?

      Group.id_in(allowed_group_ids)
    end

    def direct_groups
      user.group_members.active
    end

    def linked_groups_with_min_access_level
      group_links = GroupGroupLink.for_shared_with_groups(direct_groups.select(:source_id)).not_expired
      group_links = group_links.with_at_least_group_access(min_access_level)

      Group.id_in(group_links.select(:shared_group_id))
    end

    def target_abilities
      features = params[:features]
      return [] if features.blank?

      features.map { |feature| FEATURE_TO_ABILITY_MAP[feature.to_sym] }
    end
    strong_memoize_attr :target_abilities

    def min_access_level
      features = params[:features]
      return params.fetch(:min_access_level, DEFAULT_MIN_ACCESS_LEVEL) if features.blank?

      features.map do |feature|
        ProjectFeature.required_minimum_access_level_for_private_project(feature)
      end.min
    end
    strong_memoize_attr :min_access_level
  end
end
