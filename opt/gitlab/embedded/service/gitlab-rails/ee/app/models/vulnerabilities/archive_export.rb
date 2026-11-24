# frozen_string_literal: true

module Vulnerabilities
  class ArchiveExport < ::SecApplicationRecord
    include FileStoreMounter
    include PartitionedTable

    RETENTION_PERIOD = 1.month

    mount_file_store_uploader AttachmentUploader

    self.table_name = 'vulnerability_archive_exports'
    self.primary_key = :id

    attr_readonly :partition_number

    partitioned_by :partition_number,
      strategy: :sliding_list,
      next_partition_if: ->(partition) { requires_new_partition?(partition.value) },
      detach_partition_if: ->(partition) { detach_partition?(partition.value) }

    belongs_to :project, optional: false
    belongs_to :author, class_name: 'User', optional: false

    enum :format, { csv: 0 }

    validates :date_range, presence: true
    validates :status, presence: true
    validates :format, presence: true
    validates :file, presence: true, if: :finished?

    state_machine :status, initial: :created do
      state :created
      state :running
      state :finished
      state :failed
      state :purged

      event :start do
        transition created: :running
      end

      event :finish do
        transition running: :finished
      end

      event :failed do
        transition [:created, :running] => :failed
      end

      event :reset_state do
        transition running: :created
      end

      event :purge do
        transition any => :purged
      end

      before_transition created: :running do |export|
        export.started_at = Time.current
      end

      before_transition running: :finished do |export|
        export.finished_at = Time.current
      end

      before_transition running: :created do |export|
        export.started_at = nil
      end
    end

    class << self
      def requires_new_partition?(partition_number)
        first_record = first_record_in(partition_number)

        return unless first_record

        first_record.created_at < RETENTION_PERIOD.ago
      end

      def detach_partition?(partition_number)
        where(partition_number: partition_number).where.not(status: :purged).none?
      end

      private

      def first_record_in(partition_number)
        where(partition_number: partition_number).first
      end
    end

    def completed?
      finished? || failed?
    end

    def archives
      project.vulnerability_archives.where(date: date_range)
    end

    def uploads_sharding_key
      { project_id: project_id }
    end

    def retrieve_upload(_identifier, paths)
      Upload.find_by(model: self, path: paths)
    end
  end
end
