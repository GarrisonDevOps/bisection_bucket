# frozen_string_literal: true

module EE
  module Members
    module ImportProjectTeamService
      extend ::Gitlab::Utils::Override

      override :check_seats!
      def check_seats!
        root_namespace = target_project.root_ancestor
        invited_user_ids = source_project.project_members.pluck_user_ids

        # Members imported from another project get the same access level as whatever they have in the source project.
        # However, #seats_available_for? currently supports only a single access level for all invited users.
        # So we pass DEVELOPER and nil here, meaning we assume that all members will be billable.
        # See https://gitlab.com/gitlab-org/gitlab/-/issues/485631
        return unless root_namespace.block_seat_overages? &&
          !::GitlabSubscriptions::MemberManagement::BlockSeatOverages.seats_available_for_group?(root_namespace,
            invited_user_ids, ::Gitlab::Access::DEVELOPER, nil)

        raise ::Members::ImportProjectTeamService::SeatLimitExceededError, error_message
      end

      override :check_user_permissions!
      def check_user_permissions!
        super

        return if can?(current_user, :invite_project_members, target_project)

        raise ::Members::ImportProjectTeamService::ImportProjectTeamForbiddenError, 'Forbidden'
      end

      private

      def error_message
        messages = [
          s_('AddMember|There are not enough available seats to invite this many users.')
        ]

        unless can?(current_user, :edit_billing, target_project.root_ancestor)
          messages << s_('AddMember|Ask a user with the Owner role to purchase more seats.')
        end

        messages.join(" ")
      end
    end
  end
end
