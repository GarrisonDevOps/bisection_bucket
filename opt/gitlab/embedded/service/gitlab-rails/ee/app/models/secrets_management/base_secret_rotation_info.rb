# frozen_string_literal: true

module SecretsManagement
  class BaseSecretRotationInfo < ApplicationRecord
    self.abstract_class = true

    MIN_ROTATION_DAYS = 7
    APPROACHING_THRESHOLD_DAYS = 7

    STATUSES = {
      overdue: 'OVERDUE',
      approaching: 'APPROACHING',
      ok: 'OK'
    }.freeze

    validates :secret_name, presence: true, length: { maximum: 255 }
    validates :secret_metadata_version, presence: true
    validates :next_reminder_at, presence: true

    validates :rotation_interval_days,
      presence: true,
      numericality: { greater_than_or_equal_to: MIN_ROTATION_DAYS }

    scope :pending_reminders, -> {
      where(next_reminder_at: ..Time.current).order(next_reminder_at: :asc).includes(pending_reminders_includes)
    }

    def self.parent_id_column
      raise Gitlab::AbstractMethodError
    end

    def self.pending_reminders_includes
      raise Gitlab::AbstractMethodError
    end

    def self.for_secret(parent, name, secret_metadata_version)
      find_by(parent_id_column => parent.id, secret_name: name, secret_metadata_version: secret_metadata_version)
    end

    def upsert
      self.next_reminder_at = calculate_next_reminder_at

      return false unless valid?

      result = self.class.upsert({
        parent_id_column => parent_id,
        secret_name: secret_name,
        secret_metadata_version: secret_metadata_version,
        rotation_interval_days: rotation_interval_days,
        next_reminder_at: next_reminder_at
      }, unique_by: [parent_id_column, :secret_name, :secret_metadata_version])

      # result.rows contains `[[<id of record>]]`
      self.id = result.rows.first.first

      reset

      true
    end

    # Called by background job when notification is sent
    def notification_sent!
      update!(
        last_reminder_at: Time.current,
        next_reminder_at: calculate_next_reminder_at
      )
    end

    def status
      # During update, given we consider all updates as secret rotated,
      # last_reminder_at will be cleared. As long as last_reminder_at is present,
      # we consider it overdue rotation.
      return STATUSES[:overdue] if overdue?
      return STATUSES[:approaching] if approaching?

      STATUSES[:ok]
    end

    def needs_attention?
      overdue? || approaching?
    end

    private

    def parent_id
      raise Gitlab::AbstractMethodError
    end

    def parent_id_column
      self.class.parent_id_column
    end

    # To avoid unintentional bumping of `next_reminder_at`, we only call this
    # during `#upsert` and `#notification_sent!` instead of calling it in callbacks.
    def calculate_next_reminder_at
      return unless rotation_interval_days&.positive?

      # Always round up to the next day at 00:00 UTC
      # Example: Secret updated Sept 3rd 10pm + 7 days = reminder Sept 11th 00:00 UTC
      # This means: (Sept 4th 00:00 + 7 days) = Sept 11th 00:00 UTC
      Time.current.beginning_of_day + 1.day + rotation_interval_days.days
    end

    def overdue?
      last_reminder_at.present?
    end

    def approaching?
      next_reminder_at <= APPROACHING_THRESHOLD_DAYS.days.from_now
    end
  end
end
