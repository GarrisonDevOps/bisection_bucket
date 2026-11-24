# frozen_string_literal: true

module Users
  class ContributedGroupsFinder
    include FromUnion

    def initialize(contributor)
      @contributor = contributor
    end

    # Finds the groups "@contributor" contributed to, limited to either public groups
    # or groups visible to the given user.
    #
    # current_user - When given the list of the groups is limited to those only
    #                visible by this user.
    #
    # include_private_contributions - When true the list of groups will include all contributed
    #                                 groups, regardless of their visibility to the current_user
    #
    # Returns an ActiveRecord::Relation.
    def execute(current_user = nil, include_private_contributions: false)
      # Do not show contributed groups if the user profile is private.
      return Group.none unless Ability.allowed?(current_user, :read_user_profile, @contributor)

      epic_groups = all_epic_groups(current_user, include_private_contributions)
      note_groups = all_note_groups(current_user, include_private_contributions)

      Group.from_union(epic_groups, note_groups)
    end

    private

    def all_epic_groups(current_user, include_private_contributions)
      groups = @contributor.contributed_epic_groups
      return groups if include_private_contributions

      groups.public_or_visible_to_user(current_user)
    end

    def all_note_groups(current_user, include_private_contributions)
      groups = @contributor.contributed_note_groups
      return groups if include_private_contributions

      groups.public_or_visible_to_user(current_user)
    end
  end
end
