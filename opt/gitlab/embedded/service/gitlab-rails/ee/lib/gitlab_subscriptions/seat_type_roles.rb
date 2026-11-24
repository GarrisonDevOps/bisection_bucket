# frozen_string_literal: true

module GitlabSubscriptions
  module SeatTypeRoles
    # The highest assignable access level each seat type permits
    # Every GitlabSubscriptions::SeatAssignment seat type must appear here
    MAX_ACCESS_LEVEL_BY_SEAT_TYPE = {
      'base' => ::Gitlab::Access::OWNER,
      'free' => ::Gitlab::Access::GUEST,
      'plan' => ::Gitlab::Access::PLANNER,
      'system' => ::Gitlab::Access::OWNER,
      'security_manager' => ::Gitlab::Access::SECURITY_MANAGER
    }.freeze

    UNRESTRICTED_SEAT_TYPES = %w[base system].freeze

    class << self
      def permits_access_level?(seat_type:, access_level:, member_role:)
        seat_type = seat_type.to_s
        max_access_level = MAX_ACCESS_LEVEL_BY_SEAT_TYPE[seat_type]
        return false unless max_access_level

        return UNRESTRICTED_SEAT_TYPES.include?(seat_type) if member_role&.occupies_seat?

        access_level <= max_access_level
      end
    end
  end
end
