# frozen_string_literal: true

module GitlabSubscriptions
  module BillableUsersUtils
    include ::GitlabSubscriptions::SubscriptionHelper

    InvalidSubscriptionTypeError = Class.new(StandardError)
    InvalidMemberRoleError = Class.new(StandardError)

    # MINIMAL ACCESS are always non-billable
    # GUEST(non elevated) are non-billable on exclude_guests_from_active_count? plans, rest are billable
    def sm_billable_role_change?(role:, member_role_id: nil)
      raise InvalidSubscriptionTypeError if gitlab_com_subscription?

      return false if role == Gitlab::Access::MINIMAL_ACCESS

      return true if role > Gitlab::Access::GUEST

      return true unless License.current&.exclude_guests_from_active_count?

      member_role_billable?(member_role_id)
    end

    # MINIMAL ACCESS are always non-billable
    # GUEST(non elevated) are non-billable for groups with exclude_guests? plans, rest are billable
    def saas_billable_role_change?(target_namespace:, role:, member_role_id: nil)
      raise InvalidSubscriptionTypeError unless gitlab_com_subscription?

      return true if role > Gitlab::Access::GUEST
      return false if role == Gitlab::Access::MINIMAL_ACCESS

      return true unless target_namespace.exclude_guests?

      member_role_billable?(member_role_id)
    end

    private

    def member_role_billable?(member_role_id)
      return false unless member_role_id

      member_role = MemberRole.find_by_id(member_role_id)
      raise InvalidMemberRoleError, "Member role with ID #{member_role_id.to_i} not found." unless member_role.present?

      member_role.occupies_seat
    end
  end
end
