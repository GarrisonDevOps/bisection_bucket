# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class SessionFile < ::ApplicationRecord
      include FileStoreMounter

      MAX_SIZE = 2.megabytes
      MAX_FILENAME_LENGTH = 255
      ALLOWED_CONTENT_TYPES = %w[image/png image/jpeg image/webp].freeze

      self.table_name = :duo_workflows_session_files

      attribute :file_store, :integer, default: -> { SessionFileUploader.default_store }

      mount_file_store_uploader SessionFileUploader

      belongs_to :workflow, class_name: 'Ai::DuoWorkflows::Workflow', optional: true
      belongs_to :project, optional: true
      belongs_to :namespace, optional: true

      populate_sharding_key :project_id, source: :workflow
      populate_sharding_key :namespace_id, source: :workflow

      validates :size, presence: true, numericality: { greater_than_or_equal_to: 0, less_than_or_equal_to: MAX_SIZE }
      validates :file, presence: true
      validate :filename_length
      # Direct upload skips the uploader's `before :cache` hooks, so the type is checked here instead.
      validates :content_type, presence: true, length: { maximum: 255 }, inclusion: { in: ALLOWED_CONTENT_TYPES }

      private

      # Bytes, not chars: a local cache path is limited to 255 bytes, which also satisfies the char constraint.
      def filename_length
        return if file.filename.to_s.bytesize <= MAX_FILENAME_LENGTH

        errors.add(:file, format(_('name is too long (maximum is %{count} bytes)'), count: MAX_FILENAME_LENGTH))
      end
    end
  end
end
