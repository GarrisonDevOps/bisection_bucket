# frozen_string_literal: true

module Notifications
  class TargetedMessage < ApplicationRecord
    ALLOWED_ROLES = [
      Gitlab::Access::GUEST,
      Gitlab::Access::PLANNER,
      Gitlab::Access::REPORTER,
      Gitlab::Access::DEVELOPER,
      Gitlab::Access::MAINTAINER,
      Gitlab::Access::OWNER
    ].freeze

    validates :target_type, presence: true
    validates :starts_at, :ends_at, presence: true
    validates :roles, inclusion: { in: ALLOWED_ROLES }
    validate :starts_at_before_ends_at
    validate :starts_at_not_in_past
    validate :must_have_targeted_message_namespaces

    has_many :targeted_message_namespaces
    has_many :targeted_message_dismissals
    has_many :namespaces, through: :targeted_message_namespaces

    # these should map to wording/placement in the pajamas design doc: https://design.gitlab.com/
    enum :target_type, {
      banner_page_level: 0
    }

    def matches_current_user_access_level?(user_access_level)
      return true unless roles.present?

      roles.include?(user_access_level)
    end

    private

    def starts_at_before_ends_at
      return if starts_at.blank? || ends_at.blank?
      return if starts_at < ends_at

      errors.add(:starts_at, _('must be before ends at'))
    end

    def starts_at_not_in_past
      return if starts_at.blank?

      return unless starts_at.past?

      errors.add(:starts_at, _('cannot be in the past'))
    end

    def must_have_targeted_message_namespaces
      return unless targeted_message_namespaces.empty?

      errors.add(:base,
        s_('TargetedMessages|Must have at least one targeted namespace'))
    end
  end
end
