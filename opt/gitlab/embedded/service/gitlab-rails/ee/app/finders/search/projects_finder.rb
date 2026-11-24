# frozen_string_literal: true

# Finder for retrieving authorized projects to use for search.
#
# Returns all projects that a user has authorization to because:
# 1. They are a direct member of the project
# 2. They are a direct member of a group and the project is shared with that group
# 3. They are a direct member of a group and the project is shared with a group in the descendant hierarchy
#
# When a user has direct group memberships, projects shared via group links are
# excluded if their namespaces are already covered by the user's group hierarchy.
# The exception is when the group share link grants a higher access level than the
# user's existing membership - those projects are always included.
module Search
  class ProjectsFinder
    BATCH_SIZE = 5000

    REDIS_CACHE_TTL = 5.minutes
    CACHE_VERSION_TTL = 1.day

    def self.cache_version_key(user_id)
      "search_user:#{user_id}:projects_cache_version"
    end

    def self.cache_version(user_id)
      Rails.cache.fetch(cache_version_key(user_id), expires_in: CACHE_VERSION_TTL) { SecureRandom.hex(8) }
    end

    def self.redis_cache_key(user_id)
      "search_user:#{user_id}:v#{cache_version(user_id)}:projects"
    end

    # Bumping the per-user version orphans the current cache entry,
    # avoiding the need to enumerate variants.
    def self.expire_cache_for_users(user_ids)
      entries = user_ids.to_h { |user_id| [cache_version_key(user_id), SecureRandom.hex(8)] }
      Rails.cache.write_multi(entries, expires_in: CACHE_VERSION_TTL)
    end

    # user - The currently logged in user, if any.
    # params - Placeholder for future finder params
    def initialize(user:, _params: {})
      @user = user
    end

    def execute
      return Project.none unless user

      fetch_with_redis_cache
    end

    private

    attr_reader :user

    def fetch_with_redis_cache
      cache_key = self.class.redis_cache_key(user.id)
      cached_ids = Rails.cache.read(cache_key)

      return Project.unscoped.id_in(cached_ids) if cached_ids

      ids = fetch_projects.pluck_primary_key
      Rails.cache.write(cache_key, ids, expires_in: REDIS_CACHE_TTL)
      Project.unscoped.id_in(ids)
    end

    def fetch_projects
      Project.unscoped do
        Project
          .from_union([
            direct_projects,
            linked_through_group_projects
          ])
      end
    end

    def group_membership_source_ids
      user.authorized_groups(include_project_authorizations: false).pluck_primary_key
    end

    def project_membership_source_ids
      user.project_members.active.select(:source_id)
    end

    def direct_projects
      Project.id_in(project_membership_source_ids)
    end

    # rubocop:disable CodeReuse/ActiveRecord -- needed for finder
    def linked_through_group_projects
      group_ids = group_membership_source_ids
      return Project.none if group_ids.empty?

      trie = build_direct_group_trie
      uncovered_project_ids = []
      elevated_project_ids = []

      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by batch size
      group_ids.each_slice(BATCH_SIZE) do |group_batch|
        batch_links = find_links(group_batch)
        project_ids = batch_links.pluck('project_id').uniq
        project_namespace_ids = find_project_namespaces(project_ids).pluck('id', 'namespace_id').to_h
        namespace_traversals = Namespace.id_in(project_namespace_ids.values.uniq).pluck(:id, :traversal_ids).to_h

        batch_links.each do |link|
          namespace_id = project_namespace_ids[link['project_id']]
          traversal_ids = namespace_traversals[namespace_id]

          if trie.covered?(traversal_ids)
            covering_access = max_access_for_traversal_ids(traversal_ids)
            elevated_project_ids << link['project_id'] if link['group_access'] > covering_access
          else
            uncovered_project_ids << link['project_id']
          end
        end
      end
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit

      all_project_ids = (uncovered_project_ids + elevated_project_ids).uniq
      return Project.none if all_project_ids.empty?

      Project.id_in(all_project_ids)
    end
    # rubocop:enable CodeReuse/ActiveRecord

    def find_links(group_ids)
      sql = ProjectGroupLink
        .select(:id, :project_id, :group_access)
        .not_expired
        .where('project_group_links.group_id = ANY($1::bigint[])') # rubocop:disable CodeReuse/ActiveRecord -- needed for finder
        .to_sql
      binds = [ActiveRecord::Relation::QueryAttribute.new('group_ids', group_ids,
        ActiveRecord::Type.lookup(:integer, array: true))]
      ProjectGroupLink.connection.select_all(sql, nil, binds)
    end

    def find_project_namespaces(project_ids)
      sql = Project.select(:id, :namespace_id).where('id = ANY($1::bigint[])').to_sql # rubocop:disable CodeReuse/ActiveRecord -- needed for finder
      binds = [ActiveRecord::Relation::QueryAttribute.new('ids', project_ids,
        ActiveRecord::Type.lookup(:integer, array: true))]
      Project.connection.select_all(sql, nil, binds)
    end

    def build_direct_group_trie
      ::Namespaces::Traversal::TrieNode.build(
        Group.id_in(direct_membership_access.keys).pluck(:traversal_ids) # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- avoid instantiating whole group record
      )
    end

    def max_access_for_traversal_ids(traversal_ids)
      traversal_ids.filter_map { |ancestor_id| direct_membership_access[ancestor_id] }.max || Gitlab::Access::NO_ACCESS
    end

    def direct_membership_access
      @direct_membership_access ||= user.group_members.active
                                      .with_at_least_access_level(Gitlab::Access::GUEST)
                                      .group(:source_id) # rubocop:disable CodeReuse/ActiveRecord -- need for finder only
                                      .maximum(:access_level)
    end
  end
end
