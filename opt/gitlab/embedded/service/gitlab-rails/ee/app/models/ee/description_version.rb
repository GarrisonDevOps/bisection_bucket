# frozen_string_literal: true

module EE
  module DescriptionVersion
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    prepended do
      belongs_to :epic
      belongs_to :work_item, class_name: 'WorkItem', foreign_key: :issue_id # rubocop:disable Rails/InverseOf -- temporary

      # This scope is using `deleted_at` column which is not indexed.
      # Prevent using it in not scoped contexts.
      scope :visible, -> { where(deleted_at: nil) }
    end

    class_methods do
      def issuable_attrs
        (super + %i[epic]).freeze
      end
    end

    def issuable
      super || epic || work_item
    end

    def previous_version
      issuable_description_versions
        .where('created_at < ?', created_at)
        .order(created_at: :desc, id: :desc)
        .first
    end

    # Soft deletes a description version.
    # If start_id is given it soft deletes current version
    # up to start_id of the same issuable.
    def delete!(start_id: nil)
      start_id ||= self.id

      description_versions =
        issuable_description_versions.where('id BETWEEN ? AND ?', start_id, self.id)

      ::DescriptionVersion.id_in(description_versions).update_all(deleted_at: Time.current)

      issuable&.broadcast_notes_changed
      issuable.sync_object.broadcast_notes_changed if issuable&.try(:sync_object).present?
    end

    def deleted?
      self.deleted_at.present?
    end

    def description_diffs_available?
      issuable.present? && resource_parent.licensed_feature_available?(:description_diffs)
    end

    private

    def issuable_description_versions
      issuable.description_versions
    end
  end
end
