# frozen_string_literal: true

module Security
  module TokenStatus
    UNKNOWN = 0
    ACTIVE = 1
    INACTIVE = 2

    STATUSES = {
      unknown: UNKNOWN,
      active: ACTIVE,
      inactive: INACTIVE
    }.freeze

    # Maps a TokenLookupService#find result to a STATUSES key. Tokens without
    # active? (e.g. GroupScimAuthAccessToken) are assumed active.
    def self.for(token)
      return 'unknown' unless token
      return 'active' unless token.respond_to?(:active?)

      token.active? ? 'active' : 'inactive'
    end
  end
end
