# frozen_string_literal: true

module Import
  module Sync
    # Maps one stable GitHub object to one native GitLab record (issue, merge
    # request, note, or release), so replayed provider updates converge on the same record.
    class ExternalObject < ApplicationRecord
      self.table_name = 'import_sync_external_objects'

      belongs_to :repository,
        class_name: 'Import::Sync::Repository',
        foreign_key: :import_sync_repository_id,
        inverse_of: :external_objects,
        optional: false
      belongs_to :issue, optional: true
      belongs_to :merge_request, optional: true
      belongs_to :note, optional: true
      belongs_to :release, optional: true

      enum :kind, {
        issue: 0,
        pull_request: 1,
        issue_comment: 2,
        review_comment: 3,
        review: 4,
        release: 5
      }, prefix: true

      populate_sharding_key :project_id, source: :repository

      validates :project_id, presence: true
      validates :provider_object_xid, numericality: { only_integer: true, greater_than: 0 }
      validates :provider_object_xid, uniqueness: { scope: [:import_sync_repository_id, :kind] }
      validates :issue_id, uniqueness: true, allow_nil: true
      validates :merge_request_id, uniqueness: true, allow_nil: true
      validates :note_id, uniqueness: true, allow_nil: true
      validates :release_id, uniqueness: true, allow_nil: true
      validates_with ExactlyOnePresentValidator, associations: %i[issue merge_request note release]
      validate :repository_matches_project

      # Resolves one stable provider identity without provider I/O or mutation.
      def self.for_provider(repository:, kind:, provider_object_xid:)
        find_by(
          import_sync_repository_id: repository.id,
          kind: kinds.fetch(kind.to_s),
          provider_object_xid: provider_object_xid
        )
      end

      # Finds the mapping currently claiming a native record in this repository.
      # This lookup is used only while adopting records made by the initial import
      # and does not mutate or contact the provider.
      def self.for_local_record(repository:, local_record:)
        find_by(
          import_sync_repository_id: repository.id,
          local_record_column(local_record) => local_record.id
        )
      end

      def self.comments_on(repository:, noteable:)
        kind_issue_comment.where(import_sync_repository_id: repository.id, note_id: noteable.notes.select(:id))
      end

      def self.releases_of(repository:)
        kind_release.where(import_sync_repository_id: repository.id)
      end

      # Creates or updates one durable mapping and returns it. Concurrent callers
      # converge through the unique provider identity index.
      #
      # Two writers can both miss the initial lookup and race to claim the same
      # provider identity. Depending on timing, the loser sees either a raw DB
      # conflict (RecordNotUnique, if both inserts reach the database before either
      # validates) or a validation failure (RecordInvalid on provider_object_xid, if
      # the winner's row is already visible by the time the loser validates). Both
      # are the same race and are recovered the same way; any other RecordInvalid
      # (a different validation failing) is not this race and must not be swallowed.
      def self.record!(repository:, kind:, provider_object_xid:, local_record:, provider_updated_at:)
        mapping = for_provider(repository: repository, kind: kind, provider_object_xid: provider_object_xid) || new(
          repository: repository,
          kind: kind,
          provider_object_xid: provider_object_xid
        )

        update_mapping!(mapping, local_record: local_record, provider_updated_at: provider_updated_at)
      rescue ActiveRecord::RecordNotUnique
        resolve_provider_identity_race!(repository, kind, provider_object_xid, local_record, provider_updated_at)
      rescue ActiveRecord::RecordInvalid => e
        raise unless e.record.errors.of_kind?(:provider_object_xid, :taken)

        resolve_provider_identity_race!(repository, kind, provider_object_xid, local_record, provider_updated_at)
      end

      def self.resolve_provider_identity_race!(repository, kind, provider_object_xid, local_record, provider_updated_at)
        mapping = for_provider(repository: repository, kind: kind, provider_object_xid: provider_object_xid)
        raise unless mapping

        update_mapping!(mapping, local_record: local_record, provider_updated_at: provider_updated_at)
      end
      private_class_method :resolve_provider_identity_race!

      def self.update_mapping!(mapping, local_record:, provider_updated_at:)
        mapping.update!(
          local_record_column(local_record) => local_record.id,
          provider_updated_at: provider_updated_at
        )
        mapping
      end
      private_class_method :update_mapping!

      # Maps a record's base class to the foreign key column that stores it.
      def self.local_record_column(local_record)
        case local_record.class.base_class.name
        when 'Issue' then :issue_id
        when 'MergeRequest' then :merge_request_id
        when 'Note' then :note_id
        when 'Release' then :release_id
        else
          raise ArgumentError, "unsupported local record type: #{local_record.class.base_class.name}"
        end
      end
      private_class_method :local_record_column

      # Returns the mapped local record, whichever of the four columns is set.
      def local_record
        issue || merge_request || note || release
      end

      private

      def repository_matches_project
        return if repository.nil? || repository.project_id == project_id

        errors.add(:repository, _('must belong to the same project.'))
      end
    end
  end
end
