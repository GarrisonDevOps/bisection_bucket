# frozen_string_literal: true

module Ai
  module ActiveContext
    class Migration < ApplicationRecord
      VERSION_REGEX = /\A\d{14}\z/
      CACHE_TIMEOUT = 5.minutes

      self.table_name = :ai_active_context_migrations

      attribute :retries_left, default: 3

      enum :status, {
        pending: 0,
        in_progress: 1,
        completed: 10,
        skipped: 100,
        failed: 255
      }

      belongs_to :connection, class_name: 'Ai::ActiveContext::Connection'

      validates :version, presence: true, format: { with: VERSION_REGEX, message: 'must be a 14-digit timestamp' }
      validates :version, uniqueness: { scope: :connection_id }
      validates :status, presence: true
      validates :retries_left, numericality: { greater_than_or_equal_to: 0 }
      validate :validate_zero_retries_left, if: -> { retries_left == 0 }

      scope :processable, -> { where(status: [:pending, :in_progress]).order(:version) }
      scope :with_active_connection, -> {
        joins(:connection).where(connection: { active: true })
      }

      def self.current
        processable.first
      end

      def self.complete?(identifier)
        Rails.cache.fetch [:ai_active_context_migration_completed, identifier], expires_in: CACHE_TIMEOUT do
          check_complete_uncached(identifier)
        end
      end

      private_class_method def self.check_complete_uncached(identifier)
        version = identifier

        unless identifier.to_s.match?(VERSION_REGEX)
          version = ::ActiveContext::Migration::Dictionary.instance.find_version_by_class_name(identifier)
        end

        return false if version.nil?

        with_active_connection.where(version: version, status: :completed).exists?
      end

      def mark_as_started!
        update!(
          status: :in_progress,
          started_at: Time.zone.now
        )
      end

      def mark_as_completed!
        update!(
          status: :completed,
          completed_at: Time.zone.now
        )
      end

      def mark_as_failed!(error)
        update!(
          status: :failed,
          retries_left: 0,
          error_message: "#{error.class}: #{error.message}"
        )
      end

      def decrease_retries!(error)
        if retries_left == 1
          mark_as_failed!(error)
        else
          retries = retries_left - 1
          update!(retries_left: retries)
        end
      end

      private

      def validate_zero_retries_left
        errors.add(:retries_left, 'can only be 0 when status is failed') unless failed?
      end
    end
  end
end
