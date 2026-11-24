# frozen_string_literal: true

module GitlabSubscriptions
  class SeatAssignment < ApplicationRecord
    belongs_to :namespace, optional: false
    belongs_to :user, optional: false
    belongs_to :organization, class_name: 'Organizations::Organization', inverse_of: :seat_assignments

    validates :namespace_id, uniqueness: { scope: :user_id }, presence: { if: :gitlab_com_subscription? }

    scope :by_namespace, ->(namespace) { where(namespace: namespace) }
    scope :by_user, ->(user) { where(user: user) }
    scope :dormant_in_namespace, ->(namespace, cutoff = 90.days.ago) {
      by_namespace(namespace)
        .where('last_activity_on < ? OR (last_activity_on IS NULL AND created_at < ?)', cutoff, cutoff)
        .includes(:user)
    }

    enum :seat_type, {
      base: 0,
      free: 1,
      plan: 2,
      system: 3,
      security_manager: 4
    }

    def self.find_by_namespace_and_user(namespace, user)
      by_namespace(namespace).by_user(user).first
    end

    private

    def gitlab_com_subscription?
      ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
    end
  end
end
