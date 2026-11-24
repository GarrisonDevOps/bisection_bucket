# frozen_string_literal: true

module Authz
  # Resolves every role a user holds on a set of projects from memberships and shares,
  # instead of the single maximum stored in project_authorizations.
  #
  # Uses the same rules as Gitlab::ProjectAuthorizations, so the maximum per project matches
  # project_authorizations once it is up to date.
  class UserProjectGrants
    include Gitlab::Utils::StrongMemoize

    # Grants below Guest (Minimal Access) carry a custom role but give no project access.
    Grant = Data.define(:access_level, :member_role_id, :source) do
      def grants_access?
        access_level >= Gitlab::Access::GUEST
      end
    end

    MEMBERSHIPS_CACHE = :authz_user_project_grants_memberships

    # Forgets the user's memberships cached for the request, after they change.
    #
    # @param user_id [Integer]
    # @return [void]
    def self.forget_memberships(user_id)
      Gitlab::SafeRequestStore.delete([MEMBERSHIPS_CACHE, user_id])

      nil
    end

    # Whether the user's project access is resolved from memberships instead of project_authorizations.
    # Checked once per user for the request. Callers check it before the request cache, so the request log
    # records the source even when every lookup is answered from the cache.
    #
    # @param user_id [Integer, nil]
    # @return [Boolean]
    def self.enabled_for?(user_id)
      return false unless user_id

      enabled = Gitlab::SafeRequestStore.fetch([:authz_resolve_project_access_from_memberships, user_id]) do
        resolves_from_memberships?(user_id)
      end
      ::Gitlab::Instrumentation::Authz.record_project_access_source(enabled)

      enabled
    end

    def self.resolves_from_memberships?(user_id)
      Feature.enabled?(:resolve_project_access_from_memberships, ::User.actor_from_id(user_id))
    end

    # @param user_id [Integer, nil] nil for a user that is not persisted, who has no grants
    # @param cached [Boolean] false keeps memberships, project rows and shares on the instance instead of
    #   the request, for writers that must not see values read before they took a lock
    def initialize(user_id, cached: true)
      @user_id = user_id
      @cached = cached
    end

    # Returns every grant the user holds on each given project.
    #
    # @param projects [Array<Project, Integer>, ActiveRecord::Relation] projects, or their IDs
    # @return [Hash{Integer => Array<Grant>}] keyed by project ID, for every project that exists
    def for_projects(projects)
      return {} unless user_id

      rows = sources.project_rows(projects)
      links = sources.project_shares(rows.keys)
      load_relevant_memberships(rows, links)

      rows.to_h do |project_id, project|
        [project_id, project_grants(project_id, project, links.fetch(project_id, []))]
      end
    end

    # Returns the same shape as the project_authorizations lookup.
    #
    # @param projects [Array<Project, Integer>, ActiveRecord::Relation] projects, or their IDs
    # @return [Hash{Integer => Integer}] the highest access level per project, NO_ACCESS when there is none
    def max_access_levels(projects)
      for_projects(projects).transform_values do |grants|
        grants.select(&:grants_access?).map(&:access_level).max || Gitlab::Access::NO_ACCESS
      end
    end

    private

    attr_reader :user_id, :cached

    def project_grants(project_id, project, project_shares)
      grants = []
      grants << Grant.new(Gitlab::Access::OWNER, nil, :personal) if personal_project_owner?(project)

      memberships[:project].fetch(project_id, []).each do |membership|
        grants << Grant.new(membership[:access_level], membership[:member_role_id], :project)
      end

      grants.concat(group_grants(project[:traversal_ids])) if project[:namespace_type] == ::Group.sti_name
      # Like project_authorizations, only an explicit false allows project shares; NULL counts as locked.
      grants.concat(project_share_grants(project_shares)) if project[:share_with_group_lock] == false
      grants
    end

    # Grants on a group from direct memberships in it or its ancestors, and from group shares into them.
    def group_grants(traversal_ids)
      traversal_ids.flat_map do |group_id|
        grants = memberships[:group].fetch(group_id, []).map do |direct|
          Grant.new(direct[:access_level], direct[:member_role_id], :group)
        end

        sources.shares_into(group_id).each do |share|
          memberships[:group].fetch(share[:shared_with_group_id], []).each do |member|
            grants << shared_grant(member, share, :group_share)
          end
        end

        grants
      end
    end

    # A project share grants access to the invited group's members, including inherited ones and
    # those reaching it through a group share, capped by the share's access level. Like
    # Authz::UserProjectMemberRoles, the custom role only comes from a direct membership of the invited group.
    # Duplicate direct membership rows give one grant each, so their custom roles are all kept.
    def project_share_grants(project_shares)
      project_shares.flat_map do |share|
        best = group_grants(share[:group_traversal_ids]).select(&:grants_access?).max_by(&:access_level)
        directs = memberships[:group].fetch(share[:group_traversal_ids].last, [])
        next [] unless best || directs.any?
        next [Grant.new([best.access_level, share[:group_access]].min, nil, :project_share)] if directs.empty?

        directs.map do |direct|
          Grant.new(
            [best ? best.access_level : direct[:access_level], share[:group_access]].min,
            shared_member_role_id(direct, share),
            :project_share
          )
        end
      end
    end

    def shared_grant(member, share, source)
      Grant.new(
        [member[:access_level], share[:group_access]].min,
        shared_member_role_id(member, share),
        source
      )
    end

    # Matches Authz::MemberRoleInSharedResource: the custom role follows the side with the lower access level.
    def shared_member_role_id(member, share)
      return share[:member_role_id] if member[:access_level] > share[:group_access]
      return if member[:access_level] == share[:group_access] && share[:member_role_id].nil?

      member[:member_role_id]
    end

    def personal_project_owner?(project)
      project[:namespace_type] == ::Namespaces::UserNamespace.sti_name && project[:owner_id] == user_id
    end

    # Loads only the user's memberships that can grant access to these projects: the projects themselves,
    # groups in each project's and each invited group's hierarchy, and groups shared into those.
    # This keeps the cost independent of how many memberships the user has elsewhere.
    def load_relevant_memberships(rows, links)
      group_ids = sources.hierarchy_group_ids(rows, links)
      invited_group_ids = sources.group_shares(group_ids).values.flatten
        .filter_map { |share| share[:shared_with_group_id] }

      load_memberships(
        ::GroupMember::SOURCE_TYPE => (group_ids + invited_group_ids).uniq,
        ::ProjectMember::SOURCE_TYPE => rows.keys
      )
    end

    def sources
      ProjectGrantSources.new(cached: cached)
    end
    strong_memoize_attr :sources

    # Cached per user for the request, with every source looked up recorded so absences are not queried again.
    # Each source holds a list: members has no unique index on (user, source), so a pair can have several
    # rows, and keeping them all makes the highest level win, as in Gitlab::ProjectAuthorizations.
    def memberships
      empty = -> { { group: {}, project: {}, loaded: Set.new } }
      return empty.call unless cached

      Gitlab::SafeRequestStore.fetch([MEMBERSHIPS_CACHE, user_id], &empty)
    end
    strong_memoize_attr :memberships

    def load_memberships(source_ids_by_type)
      wanted = source_ids_by_type.flat_map { |type, ids| ids.map { |id| [type, id] } }
        .reject { |key| memberships[:loaded].include?(key) }
      return if wanted.empty?

      queried_memberships(wanted).each do |source_type, source_id, access_level, member_role_id|
        target = source_type == ::ProjectMember::SOURCE_TYPE ? :project : :group
        (memberships[target][source_id] ||= []) << { access_level: access_level, member_role_id: member_role_id }
      end
      memberships[:loaded].merge(wanted)
    end

    # Joining unnested arrays probes the (user_id, source_id, source_type) index once per source,
    # and keeps planning flat however many sources are wanted.
    def queried_memberships(wanted)
      types, ids = wanted.transpose
      wanted_join = ::Member.sanitize_sql_array([
        'INNER JOIN unnest(?::bigint[], ?::text[]) AS wanted(source_id, source_type) ' \
          'ON wanted.source_id = members.source_id AND wanted.source_type = members.source_type',
        pg_array(ids.map { |id| Integer(id) }), pg_array(types)
      ])

      ::Member.where(user_id: user_id).non_request.active_state.joins(wanted_join)
        .pluck(:source_type, :source_id, :access_level, :member_role_id) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by the sources being checked
    end

    def pg_array(values)
      "{#{values.join(',')}}"
    end
  end
end
