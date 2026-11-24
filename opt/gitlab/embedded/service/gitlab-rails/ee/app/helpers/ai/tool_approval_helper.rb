# frozen_string_literal: true

module Ai
  module ToolApprovalHelper
    AVAILABILITY_MAP = {
      default_on: { enabled: true, lock: false },
      default_off: { enabled: false, lock: false },
      never_on: { enabled: false, lock: true }
    }.freeze

    # Maps the two boolean columns to a three-state availability symbol.
    # Lock takes precedence: (enabled: true, lock: true) normalizes to :never_on.
    def self.to_session_availability(enabled, locked)
      if locked
        :never_on
      elsif enabled
        :default_on
      else
        :default_off
      end
    end

    def self.enabled_for_session_availability(value)
      result = AVAILABILITY_MAP.fetch(value.to_sym)

      result[:enabled]
    end

    def self.locked_for_session_availability(value)
      result = AVAILABILITY_MAP.fetch(value.to_sym)

      result[:lock]
    end
  end
end
