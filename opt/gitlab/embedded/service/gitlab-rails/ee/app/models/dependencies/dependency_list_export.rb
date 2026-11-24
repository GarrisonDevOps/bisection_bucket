# frozen_string_literal: true

module Dependencies
  class DependencyListExport < ::SecApplicationRecord
    include FileStoreMounter
    include Ci::Partitionable::AssociationFinder

    MAX_EXPORT_DURATION = 24.hours
    EXPIRES_AFTER = 7.days

    mount_file_store_uploader AttachmentUploader

    belongs_to :organization, class_name: 'Organizations::Organization'
    belongs_to :project
    belongs_to :group
    belongs_to :pipeline, class_name: 'Ci::Pipeline'
    partitionable_belongs_to_loader :pipeline
    belongs_to :author, class_name: 'User', foreign_key: :user_id, inverse_of: :dependency_list_exports

    # rubocop:disable Cop/ActiveRecordDependent -- legacy usage
    has_many :export_parts, class_name: 'Dependencies::DependencyListExport::Part', dependent: :destroy
    # rubocop:enable Cop/ActiveRecordDependent -- legacy usage

    validates :status, presence: true
    validates :file, presence: true, if: :finished?
    validates :export_type, presence: true

    validate :only_one_exportable

    enum :export_type, {
      dependency_list: 0,
      sbom: 1,
      json_array: 2,
      csv: 3,
      cyclonedx_1_6_json: 10
    }

    scope :expired, -> { where(expires_at: ..Time.zone.now) }
    scope :for_group, ->(group) { where(group: group) }
    scope :for_project, ->(project) { where(project: project) }

    state_machine :status, initial: :created do
      state :created, value: 0
      state :running, value: 1
      state :finished, value: 2
      state :failed, value: -1

      event :start do
        transition created: :running
      end

      event :finish do
        transition running: :finished
      end

      event :reset_state do
        transition running: :created
      end

      event :failed do
        transition [:created, :running] => :failed
      end
    end

    def completed?
      finished? || failed?
    end

    def retrieve_upload(_identifier, paths)
      Upload.find_by(model: self, path: paths)
    end

    def exportable
      # Order is important. Pipeline exports also have a project.
      pipeline || project || group
    end

    def exportable=(value)
      case value
      when Project
        self.project = value
      when Group
        self.group = value
      when Ci::Pipeline
        self.pipeline = value
        # `project_id` is used as sharding key for cells
        self.project = value.project
      end
    end

    def export_service
      Dependencies::Export::SegmentedExportService.new(self) # rubocop:disable CodeReuse/ServiceClass -- This interface is expected by segmented export framework
    end

    def send_completion_email!
      return unless send_email?

      Sbom::ExportMailer.completion_email(self).deliver_now
    end

    def schedule_export_deletion
      update!(expires_at: EXPIRES_AFTER.from_now)
    end

    def timed_out?
      created_at < MAX_EXPORT_DURATION.ago
    end

    def uploads_sharding_key
      {
        organization_id: organization_id,
        namespace_id: group_id,
        project_id: project_id
      }
    end

    private

    def only_one_exportable
      # When we have a pipeline, it is ok to also have a project. All pipeline exports _should_
      # have a project, but we must backfill existing records before we can validate this.
      # https://gitlab.com/gitlab-org/gitlab/-/issues/454947
      return if pipeline.present? && project.present? && group.blank?

      errors.add(:base, 'Only one exportable is required') unless [project, group, pipeline].one?
    end
  end
end
