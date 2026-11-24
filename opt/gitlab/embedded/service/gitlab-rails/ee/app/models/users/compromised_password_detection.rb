# frozen_string_literal: true

module Users
  class CompromisedPasswordDetection < ::ApplicationRecord
    belongs_to :user

    validates_uniqueness_of :user_id, scope: :resolved_at, if: -> { resolved_at.nil? }

    scope :unresolved, -> { where(resolved_at: nil) }
  end
end
