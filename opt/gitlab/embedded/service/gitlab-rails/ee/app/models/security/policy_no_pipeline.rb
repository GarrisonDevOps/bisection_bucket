# frozen_string_literal: true

module Security
  module PolicyNoPipeline
    def no_pipeline_allowed_for_strategy?(strategy, user_id)
      allowed = strategy[:allowed]
      allowlist = strategy.dig(:allowlist, :users)

      return allowed if allowed || allowlist.blank?

      allowlist.any? { |user| user[:id] == user_id }
    end
  end
end
