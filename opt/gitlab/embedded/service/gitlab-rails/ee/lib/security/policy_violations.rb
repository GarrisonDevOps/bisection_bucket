# frozen_string_literal: true

module Security
  module PolicyViolations
    NOT_APPLICABLE = 0
    DISMISSED_IN_MR = 1

    VIOLATIONS_TYPES = {
      not_applicable: NOT_APPLICABLE,
      dismissed_in_mr: DISMISSED_IN_MR
    }.freeze
  end
end
