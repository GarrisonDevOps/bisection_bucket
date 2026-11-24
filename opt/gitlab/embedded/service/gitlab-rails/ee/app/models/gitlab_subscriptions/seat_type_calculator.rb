# frozen_string_literal: true

module GitlabSubscriptions
  class SeatTypeCalculator
    BASE_SEAT = :base
    FREE_SEAT = :free
    PLAN_SEAT = :plan
    SYSTEM_SEAT = :system
    SECURITY_MANAGER_SEAT = :security_manager

    FREE_TIER = :free
    PREMIUM_TIER = :premium
    ULTIMATE_TIER = :ultimate

    SEAT_TYPE_MAPPINGS = {
      premium: {
        ::Gitlab::Access::MINIMAL_ACCESS => FREE_SEAT,
        ::Gitlab::Access::GUEST => BASE_SEAT,
        ::Gitlab::Access::PLANNER => BASE_SEAT,
        ::Gitlab::Access::REPORTER => BASE_SEAT,
        ::Gitlab::Access::SECURITY_MANAGER => BASE_SEAT,
        ::Gitlab::Access::DEVELOPER => BASE_SEAT,
        ::Gitlab::Access::MAINTAINER => BASE_SEAT,
        ::Gitlab::Access::OWNER => BASE_SEAT
      },
      ultimate: {
        ::Gitlab::Access::MINIMAL_ACCESS => FREE_SEAT,
        ::Gitlab::Access::GUEST => FREE_SEAT,
        ::Gitlab::Access::PLANNER => PLAN_SEAT,
        ::Gitlab::Access::REPORTER => BASE_SEAT,
        ::Gitlab::Access::SECURITY_MANAGER => SECURITY_MANAGER_SEAT,
        ::Gitlab::Access::DEVELOPER => BASE_SEAT,
        ::Gitlab::Access::MAINTAINER => BASE_SEAT,
        ::Gitlab::Access::OWNER => BASE_SEAT
      }
    }.freeze

    class << self
      def execute(user, root_namespace)
        return unless gitlab_com?

        user = resolve_user(user)
        tier = subscription_tier(root_namespace)
        membership_details = seat_assignable_member_details(user, root_namespace)[user.id]

        calculate_seat_type(user, tier, membership_details)
      end

      def bulk_execute(users, root_namespace)
        return {} unless gitlab_com?

        users = resolve_users(users)
        tier = subscription_tier(root_namespace)
        membership_details_by_user_id = seat_assignable_member_details(users, root_namespace)

        users.compact.each_with_object({}) do |user, hash|
          membership_details = membership_details_by_user_id[user.id]
          hash[user.id] = calculate_seat_type(user, tier, membership_details)
        end
      end

      private

      def resolve_user(user)
        user.is_a?(User) ? user : User.find_by(id: user)
      end

      def resolve_users(users)
        users.is_a?(ActiveRecord::Relation) ? users : User.where(id: users)
      end

      def gitlab_com?
        ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      end

      def seat_assignable_member_details(users, root_namespace)
        Member.seat_assignable(users: users, namespace: root_namespace)
          .left_joins(:member_role)
          .group(:user_id)
          .select(
            :user_id,
            "MAX(members.access_level) AS max_access_level",
            "COALESCE(BOOL_OR(member_roles.occupies_seat), false) AS has_billable_custom_role"
          )
          .index_by(&:user_id)
      end

      def calculate_seat_type(user, tier, membership_details)
        return unless membership_details
        return SYSTEM_SEAT if user.bot?
        return BASE_SEAT if tier == FREE_TIER
        return BASE_SEAT if billable_custom_role?(tier, membership_details)

        access_level = membership_details.max_access_level
        SEAT_TYPE_MAPPINGS.dig(tier, access_level)
      end

      def subscription_tier(root_namespace)
        return FREE_TIER if root_namespace.free_plan?

        root_namespace.exclude_guests? ? ULTIMATE_TIER : PREMIUM_TIER
      end

      def billable_custom_role?(tier, membership_details)
        tier == ULTIMATE_TIER && membership_details.has_billable_custom_role
      end
    end
  end
end
