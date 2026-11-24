# frozen_string_literal: true

module Ci
  module TestBalancing
    class TestSplit < Ci::ApplicationRecord
      include BulkInsertSafe

      belongs_to :project

      validates :path, presence: true, length: { maximum: 1024 }

      # Returns a { id => path } hash for the given test split ids of a project.
      def self.paths_by_id(project_id, ids)
        where(project_id: project_id, id: ids).limit(MAX_TEST_SPLITS_PER_JOB_GROUP).pluck(:id, :path).to_h
      end

      # Returns a { path => id } hash for the given test split paths of a project.
      def self.ids_by_path(project_id, paths)
        where(project_id: project_id, path: paths).limit(MAX_TEST_SPLITS_PER_JOB_GROUP).pluck(:path, :id).to_h
      end

      # Returns a complete { path => id } map for the given paths, creating any
      # that do not exist yet.
      #
      # The common case is that every path already exists, so we look the ids up
      # first and only insert the paths that are missing. This avoids the dead
      # tuples an unconditional INSERT ... ON CONFLICT DO NOTHING would create
      # for already-present rows.
      #
      # Validations run via BulkInsertSafe, so an invalid path (blank or too
      # long) raises ActiveRecord::RecordInvalid.
      def self.fetch_or_create_ids!(project_id, paths)
        paths = paths.uniq
        existing = ids_by_path(project_id, paths)

        touch_last_seen(existing.values)

        missing = paths - existing.keys
        return existing if missing.empty?

        now = Time.current
        records = missing.map { |path| new(project_id: project_id, path: path, last_seen_at: now) }

        inserted = bulk_insert!(
          records,
          skip_duplicates: true,
          unique_by: [:project_id, :path],
          returns: %w[path id]
        )

        result = existing.merge(inserted.to_h)

        # A concurrent insert can skip some of our rows (ON CONFLICT DO NOTHING),
        # so they are absent from the RETURNING set; fetch those stragglers.
        stragglers = paths - result.keys
        return result if stragglers.empty?

        result.merge(ids_by_path(project_id, stragglers))
      end

      def self.touch_last_seen(ids)
        return if ids.empty?

        where(id: ids)
          .where(last_seen_at: ...LAST_SEEN_THROTTLE_INTERVAL.ago)
          .update_all(last_seen_at: Time.current)
      end
    end
  end
end
