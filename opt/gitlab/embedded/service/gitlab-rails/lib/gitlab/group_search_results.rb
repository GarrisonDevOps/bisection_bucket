# frozen_string_literal: true

module Gitlab
  class GroupSearchResults < SearchResults
    extend ::Gitlab::Utils::Override
    include ::Gitlab::Utils::StrongMemoize

    attr_reader :group

    def initialize(current_user, query, limit_projects = nil, group:, **opts)
      @group = group
      super(
        current_user,
        query,
        limit_projects,
        default_project_filter: opts.fetch(:default_project_filter, false),
        order_by: opts.fetch(:order_by, nil),
        sort: opts.fetch(:sort, nil),
        filters: opts.fetch(:filters, {})
      )
    end

    def users
      return User.none unless Ability.allowed?(current_user, :read_group_member, group)

      groups = group.self_and_hierarchy_intersecting_with_user_groups(current_user)
      member_ids = GroupMember.of_groups(groups).non_invite.select(:user_id)

      users = super

      users.id_in(member_ids)
    end

    override :milestones
    def milestones
      search_term = Milestone.search(query)
      filter_milestones_by_group(search_term).order_updated_desc
    end

    def issuable_params
      super.merge(group_id: group.id, include_subgroups: true)
    end

    private

    def filter_milestones_by_group(milestones)
      authorized_groups = milestone_groups_visible_to_user
      authorized_groups = authorized_groups.non_archived unless filters[:include_archived]

      candidate_projects = project_ids_relation
      candidate_projects = candidate_projects.self_and_ancestors_non_archived unless filters[:include_archived]
      authorized_projects = Project.id_in(candidate_projects).with_issues_or_mrs_available_for_user(current_user)
                                   .select(:id)

      return Milestone.none unless authorized_groups.exists? || authorized_projects.exists?

      milestones.for_projects_and_groups(authorized_projects, authorized_groups.select(:id))
    end

    # Same groups as `self_and_hierarchy.public_or_visible_to_user`, but cheaper: that check builds all of the
    # user's authorized groups once per private group, which is slow for users with many memberships.
    def milestone_groups_visible_to_user
      return group.self_and_hierarchy.public_or_visible_to_user(current_user) unless current_user

      ancestors = Group.id_in(visible_ancestor_ids)
      groups = group.self_and_descendants
      return groups.or(ancestors) if group_member?

      groups.public_to_user(current_user)
        .or(groups_visible_through_membership(groups))
        .or(groups.id_in(groups_with_authorized_projects.select(:id)))
        .or(ancestors)
    end

    # Same rules as `User#authorized_groups(include_project_authorizations: false)`. Keep the two in sync.
    def groups_visible_through_membership(groups)
      groups.with_user_membership_in_lineage(current_user).or(groups.with_user_share_in_lineage(current_user))
    end

    # Returns the groups a user can read through a project membership in the searched hierarchy:
    # the project's group and that group's ancestors.
    #
    # @return [ActiveRecord::Relation<Group>]
    def groups_with_authorized_projects
      project_namespace_ids = current_user.authorized_projects.for_group_and_its_subgroups(group).select(:namespace_id)

      Group.id_in(project_namespace_ids).self_and_ancestors
    end

    def visible_ancestor_ids
      group.ancestors.public_or_visible_to_user(current_user).pluck_primary_key
    end
    strong_memoize_attr :visible_ancestor_ids

    def group_member?
      group.max_member_access_for_user(current_user, only_concrete_membership: true) >= Gitlab::Access::GUEST
    end
    strong_memoize_attr :group_member?
  end
end

Gitlab::GroupSearchResults.prepend_mod_with('Gitlab::GroupSearchResults')
