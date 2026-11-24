# frozen_string_literal: true

module GitlabSubscriptions
  module SeatThresholds
    # For smaller subscriptions we want to alert when they have a set quantity of seats remaining.
    # For larger subscriptions we want to alert them when they have a percentage of seats remaining.
    LIMITS = [
      { range: (0..15), percentage: false, value: 1 },
      { range: (16..25), percentage: false, value: 2 },
      { range: (26..99), percentage: true, value: 10 },
      { range: (100..999), percentage: true, value: 8 },
      { range: (1000..nil), percentage: true, value: 5 }
    ].freeze

    # Subscriptions with this many seats or fewer are considered small. For these, being at the seat
    # limit is the normal, expected state rather than an actionable signal, so seat-limit alerts are
    # suppressed entirely (see https://gitlab.com/gitlab-org/gitlab/-/issues/604240).
    SMALL_SUBSCRIPTION_MAX_SEATS = 2

    def self.small_subscription?(seats_total)
      return false unless seats_total

      seats_total <= SMALL_SUBSCRIPTION_MAX_SEATS
    end

    def self.threshold_reached?(seats_total:, seats_used:)
      return false unless seats_total && seats_used
      return true if seats_used >= seats_total

      threshold = LIMITS.find { |limit| limit[:range].cover?(seats_total) }
      return false unless threshold

      remaining = seats_total - seats_used
      remaining_value = threshold[:percentage] ? (remaining.fdiv(seats_total) * 100) : remaining

      threshold[:value] >= remaining_value
    end
  end
end
