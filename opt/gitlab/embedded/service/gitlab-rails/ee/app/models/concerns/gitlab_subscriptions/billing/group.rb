# frozen_string_literal: true

module GitlabSubscriptions
  module Billing
    module Group
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override
      include Gitlab::Utils::StrongMemoize

      override :billable_members_count
      def billable_members_count(requested_hosted_plan = nil)
        billable_ids = billed_user_ids(requested_hosted_plan)

        billable_ids[:user_ids].count
      end

      # For now, we are not billing for members with a Guest role for subscriptions
      # with a Gold/Ultimate plan. The other plans will treat Guest members as a regular member
      # for billing purposes.
      #
      # For the user_ids key, we are plucking the user_ids from the "Members" table in an array and
      # converting the array of user_ids to a Set which will have unique user_ids.
      override :billed_user_ids
      def billed_user_ids(requested_hosted_plan = nil)
        exclude_guests?(requested_hosted_plan) ? billed_user_ids_excluding_guests : billed_user_ids_including_guests
      end

      override :exclude_guests?
      def exclude_guests?(requested_hosted_plan = nil)
        (
          [actual_plan_name, requested_hosted_plan] &
            [::GitlabSubscriptions::SystemDefined::Plan::GOLD, ::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE, ::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE_TRIAL]
        ).any?
      end

      def billed_group_users(exclude_guests: false)
        members = billed_group_members(exclude_guests: exclude_guests)
        billed_users_from_members(members)
      end

      def billed_group_members(exclude_guests: false)
        members = ::GroupMember.active_without_invites_and_requests.where(
          source_id: self_and_descendants
        )
        members = members.with_elevated_guests if exclude_guests

        members.not_banned_in(root_ancestor)
      end

      # Members belonging directly to Projects within Group or Projects within subgroups
      def billed_project_users(exclude_guests: false)
        members = billed_project_members(exclude_guests: exclude_guests, select: [:user_id])
        billed_users_from_members(members, merge_condition: ::User.with_state(:active))
          .allow_cross_joins_across_databases(url: 'https://gitlab.com/gitlab-org/gitlab/-/issues/417464')
      end

      def billed_project_members(exclude_guests: false, select: [])
        members = ::ProjectMember.without_invites_and_requests
          .where(source_id: ::Project.joins(:group).where(namespace: self_and_descendants))
          .not_banned_in(root_ancestor)

        if exclude_guests
          billed_elevated_guest_custom_roles_in_group_hierarchy = ::MemberRole.occupies_seat
            .by_namespace(self_and_descendants)
            .select(:id)

          billed_custom_role_members = ::ProjectMember.without_invites_and_requests
            .with_member_role_id(billed_elevated_guest_custom_roles_in_group_hierarchy)
            .not_banned_in(root_ancestor)

          ::Member.from_union([members.non_guests.select(select), billed_custom_role_members.select(select)])
        else
          members
        end
      end

      # Members belonging to Groups invited to collaborate with Groups and Subgroups
      def billed_shared_group_users(exclude_guests: false)
        members = billed_shared_group_members(exclude_guests: exclude_guests)
        billed_users_from_members(members)
      end

      def billed_shared_group_members(exclude_guests: false)
        groups = self.class.invited_groups_in_groups_for_hierarchy(self, exclude_guests)

        # gets all billable members from group-invites with access_level > GUEST
        members = invited_or_shared_group_members(groups, exclude_guests: exclude_guests)

        # gets all billable members from group-invites with access_level = GUEST + custom_role
        members_with_custom_role = billed_shared_guest_group_members_with_custom_role(exclude_guests: exclude_guests)

        # merge both and return
        # see acceptance criteria - https://gitlab.com/gitlab-org/gitlab/-/issues/443369#note_2045035173
        ::GroupMember.from_union([members, members_with_custom_role]).not_banned_in(root_ancestor)
      end

      def billed_shared_guest_group_members_with_custom_role(exclude_guests: false)
        return ::GroupMember.none unless exclude_guests

        # invited groups that have access_level = GUEST + custom_role
        groups = self.class.invited_groups_with_guest_member_role(self)

        # get all members from those invited groups that have
        # access_level = GUEST + custom_role (that has occupies_seat = TRUE)
        members_with_elevating_guest_member_role(groups)
      end

      # Members belonging to Groups invited to collaborate with Projects
      def billed_invited_group_to_project_users(exclude_guests: false)
        members = billed_invited_group_to_project_members(exclude_guests: exclude_guests)
        billed_users_from_members(members)
      end

      def billed_invited_group_to_project_members(exclude_guests: false)
        groups = self.class.invited_groups_in_projects_for_hierarchy(self, exclude_guests)
        invited_or_shared_group_members(groups, exclude_guests: exclude_guests).not_banned_in(root_ancestor)
      end

      # Thin wrapper to promote a source of truth for filtering billed users as we
      # filter the users from members outside this class as well.
      def billed_users_from_members(members, merge_condition: ::User.all)
        users_without_bots(members, merge_condition: merge_condition)
      end

      private

      def billed_user_ids_excluding_guests
        ::Namespaces::BilledUsersFinder.new(self, exclude_guests: true).execute
      end
      strong_memoize_attr :billed_user_ids_excluding_guests

      def billed_user_ids_including_guests
        ::Namespaces::BilledUsersFinder.new(self).execute
      end
      strong_memoize_attr :billed_user_ids_including_guests

      def invited_or_shared_group_members(groups, exclude_guests: false)
        non_guests_scope = ::GroupMember.with_elevated_guests
        guests_scope = exclude_guests ? non_guests_scope : ::GroupMember.all

        ::GroupMember.active_without_invites_and_requests
          .with_source_id(groups.self_and_ancestors)
          .merge(guests_scope)
      end
    end
  end
end
