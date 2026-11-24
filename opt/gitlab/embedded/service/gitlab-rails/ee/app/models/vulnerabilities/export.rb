# frozen_string_literal: true

module Vulnerabilities
  class Export < ::SecApplicationRecord
    include Gitlab::Utils::StrongMemoize
    include FileStoreMounter

    EXPORTER_CLASS = {
      csv: VulnerabilityExports::ExportService,
      pdf: VulnerabilityExports::PdfExportService
    }.freeze
    MAX_EXPORT_DURATION = 24.hours
    EXPIRES_AFTER = 7.days
    RECENT_WINDOW = 1.hour

    self.table_name = "vulnerability_exports"

    belongs_to :project
    belongs_to :group
    belongs_to :author, optional: false, class_name: 'User'
    belongs_to :organization, class_name: 'Organizations::Organization'

    has_many :export_parts, class_name: 'Vulnerabilities::Export::Part', foreign_key: 'vulnerability_export_id',
      dependent: :destroy, inverse_of: :vulnerability_export # rubocop:disable Cop/ActiveRecordDependent -- legacy usage

    mount_file_store_uploader AttachmentUploader

    enum :format, {
      csv: 0,
      pdf: 1
    }

    attribute :report_data, ::Gitlab::Database::Type::IndifferentJsonb.new, default: -> { {} }
    attribute :filters, ::Gitlab::Database::Type::IndifferentJsonb.new, default: -> { {} }

    # rubocop:disable Database/JsonbSizeLimit -- exports are ephemeral
    validates :report_data, json_schema: { filename: 'vulnerabilities_export' }
    validates :filters, json_schema: { filename: 'vulnerability_export_filters' }
    # rubocop:enable Database/JsonbSizeLimit
    validates :status, presence: true
    validates :format, presence: true
    validates :file, presence: true, if: :finished?
    validate :only_one_exportable

    scope :expired, -> { where(expires_at: ..Time.zone.now) }
    scope :recent, -> { where(created_at: RECENT_WINDOW.ago..) }
    scope :in_progress, -> { where(status: [:created, :running]) }
    scope :for_author, ->(author) { where(author: author) }
    scope :for_group, ->(group) { where(group: group) }
    scope :for_project, ->(project) { where(project: project) }
    scope :instance, -> { where(group: nil, project: nil) }

    state_machine :status, initial: :created do
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

      state :created
      state :running
      state :finished
      state :failed

      before_transition created: :running do |export|
        export.started_at = Time.current
      end

      before_transition any => [:finished, :failed] do |export|
        export.finished_at = Time.current
      end
    end

    def exportable
      project || group || author.security_dashboard
    end

    def exportable=(value)
      case value
      when Project
        make_project_level_export(value)
      when Group
        make_group_level_export(value)
      when InstanceSecurityDashboard
        make_instance_level_export(value)
      else
        raise "Can not assign #{value.class} as exportable"
      end
    end

    def completed?
      finished? || failed?
    end

    def retrieve_upload(_identifier, paths)
      Upload.find_by(model: self, path: paths)
    end

    def export_service
      EXPORTER_CLASS[self.format.to_sym].new(self)
    end

    def schedule_export_deletion
      update!(expires_at: EXPIRES_AFTER.from_now)
    end

    def timed_out?
      created_at < MAX_EXPORT_DURATION.ago
    end

    def uploads_sharding_key
      { organization_id: organization_id }
    end

    def send_completion_email!
      return unless send_email?

      Vulnerabilities::ExportMailer.completion_email(self).deliver_now
    end

    private

    def make_project_level_export(project)
      self.project = project
      self.group = nil
      self.organization_id = set_organization(project.namespace)
    end

    def make_group_level_export(group)
      self.group = group
      self.project = nil
      self.organization_id = set_organization(group)
    end

    def make_instance_level_export(security_dashboard)
      self.project = self.group = nil
      self.organization_id = set_organization(security_dashboard.user.namespace)
    end

    def set_organization(namespace)
      namespace.organization_id
    end

    def only_one_exportable
      errors.add(:base, _('Project & Group can not be assigned at the same time')) if project && group
    end
  end
end
