# frozen_string_literal: true

module ComplianceManagement
  class PiplUser < ApplicationRecord
    LEVEL_1_NOTIFICATION_TIME = 30.days
    LEVEL_2_NOTIFICATION_TIME = 53.days
    LEVEL_3_NOTIFICATION_TIME = 59.days

    NOTICE_PERIOD = 60.days
    DELETION_PERIOD = 120.days

    belongs_to :user, optional: false

    scope :days_from_initial_pipl_email, ->(*days) do
      sent_mail_ranges = days.map do |day_count|
        day_count.ago.beginning_of_day..day_count.ago.end_of_day
      end

      includes(:user).where(initial_email_sent_at: sent_mail_ranges)
    end

    scope :with_due_notifications, -> do
      days_from_initial_pipl_email(*[LEVEL_1_NOTIFICATION_TIME, LEVEL_2_NOTIFICATION_TIME, LEVEL_3_NOTIFICATION_TIME])
    end

    scope :pipl_email_sent_on_or_before, ->(date) do
      where(initial_email_sent_at: ..date)
    end

    scope :pipl_blockable, -> do
      joins(:user)
        .includes(:user)
        .pipl_email_sent_on_or_before(NOTICE_PERIOD.ago.end_of_day)
        .where.not(users: { state: ::User.state_machine.states[:blocked].value })
    end

    scope :pipl_deletable, -> do
      joins(:user)
        .includes(user: :organization)
        .left_outer_joins(user: :ghost_user_migration)
        .where(ghost_user_migrations: { id: nil })
        .pipl_email_sent_on_or_before(DELETION_PERIOD.ago.end_of_day)
        .merge(User.blocked)
    end

    validates :last_access_from_pipl_country_at, presence: true

    enum :state, {
      default: 0
    }

    def self.for_user(user)
      find_by(user: user)
    end

    def self.untrack_access!(user)
      where(user: user).delete_all if user.is_a?(User)
    end

    def self.track_access(user)
      upsert({ user_id: user.id, last_access_from_pipl_country_at: Time.current }, unique_by: :user_id)
    end

    def recently_tracked?
      last_access_from_pipl_country_at.after?(24.hours.ago)
    end

    def pipl_access_end_date
      return if initial_email_sent_at.blank?

      initial_email_sent_at.to_date + NOTICE_PERIOD
    end

    def reset_notification!
      update(initial_email_sent_at: nil)
    end

    def remaining_pipl_access_days
      return if initial_email_sent_at.blank?

      (pipl_access_end_date - Date.current).to_i
    end

    def block_threshold_met?
      initial_email_sent_at.present? &&
        initial_email_sent_at.to_date <= (Date.current - NOTICE_PERIOD)
    end

    def deletion_threshold_met?
      initial_email_sent_at.present? &&
        initial_email_sent_at.to_date <= (Date.current - DELETION_PERIOD)
    end
  end
end
