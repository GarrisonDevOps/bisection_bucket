# frozen_string_literal: true

module Import
  module Sync
    # Stores one repository's generation progress, checkpoint, and sanitized health
    # for one sync domain (inventory, source, work_items, or lfs).
    class RepositoryState < ApplicationRecord
      self.table_name = 'import_sync_repository_states'

      belongs_to :repository,
        class_name: 'Import::Sync::Repository',
        foreign_key: :import_sync_repository_id,
        inverse_of: :sync_states,
        optional: false

      enum :domain, { inventory: 0, source: 1, work_items: 2, lfs: 3 }, prefix: true
      enum :state, {
        pending: 0,
        running: 1,
        current: 2,
        delayed: 3,
        degraded: 4,
        paused: 5,
        disconnected: 6
      }

      populate_sharding_key :project_id, source: :repository

      validates :project_id, presence: true
      validates :domain, uniqueness: { scope: :import_sync_repository_id }
      validates :desired_generation, :synced_generation,
        numericality: { only_integer: true, greater_than_or_equal_to: 0 }
      validates :cursor, length: { maximum: 2048 }, allow_nil: true
      validates :last_error_code, length: { maximum: 255 }, allow_nil: true
      validates :last_error_message, length: { maximum: 1024 }, allow_nil: true
      validate :repository_matches_project
      validate :synced_generation_does_not_exceed_desired_generation

      # Returns whether this domain still has requested work not fully applied.
      # It is a deterministic generation comparison and does not mutate state.
      def lagging?
        desired_generation > synced_generation
      end

      private

      # Keeps domain state on the same project as its repository. It
      # reports a validation error and has no external or persistence side effect.
      def repository_matches_project
        return if repository.nil? || repository.project_id == project_id

        errors.add(:repository, _('must belong to the same project.'))
      end

      # Preserves the monotonic progress invariant used for coalescing. It reports
      # invalid generation order without changing either counter.
      def synced_generation_does_not_exceed_desired_generation
        return if desired_generation.nil? || synced_generation.nil?
        return if synced_generation <= desired_generation

        errors.add(:synced_generation, _('must not exceed the desired generation.'))
      end
    end
  end
end
