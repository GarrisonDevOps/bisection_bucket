# frozen_string_literal: true

module EE
  module MembershipActions
    extend ::Gitlab::Utils::Override

    private

    def update_params
      super.merge(params.require(root_params_key).permit(:member_role_id))
    end

    override :update_success_response
    def update_success_response(result)
      response_data = {}
      response_data = super if result[:members].present?
      if result[:members_queued_for_approval].present?
        response_data[:enqueued] = true
      end
      # Add in the seat usage info, frontend needs this to update the "is using seat" badge.
      member = result[:members]&.first
      if member.present?
        response_data[:using_license] =
          can?(current_user, :read_billable_member, member.group) && member.user&.using_gitlab_com_seat?(member.group)
      end

      response_data
    end
  end
end
