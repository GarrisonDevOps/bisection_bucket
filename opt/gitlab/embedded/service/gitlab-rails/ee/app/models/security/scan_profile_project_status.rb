# frozen_string_literal: true

module Security
  class ScanProfileProjectStatus < ::SecApplicationRecord
    self.table_name = 'security_scan_profile_project_statuses'

    STALE_THRESHOLD_DAYS = 90
    FAILED_THRESHOLD = 3

    belongs_to :project
    belongs_to :scan_profile, class_name: 'Security::ScanProfile',
      foreign_key: :security_scan_profile_id, inverse_of: :security_scan_profile_project_statuses
    belongs_to :build, class_name: 'Ci::Build', optional: true

    enum :status, Enums::Security.scan_profile_statuses

    validates :status, presence: true
    validates :consecutive_failure_count, numericality: { greater_than_or_equal_to: 0 }
    validates :consecutive_success_count, numericality: { greater_than_or_equal_to: 0 }

    scope :by_project, ->(project_id) { where(project_id: project_id) }
    scope :for_projects_and_profile, ->(project_ids, profile_id) {
      where(project_id: project_ids, security_scan_profile_id: profile_id)
    }
    scope :for_scan_profile, ->(scan_profile_id) { where(security_scan_profile_id: scan_profile_id) }
    scope :with_not_deleted_scan_profile, -> { joins(:scan_profile).merge(Security::ScanProfile.not_deleted) }

    def stale?
      !not_configured? && last_scan_at.present? && last_scan_at < STALE_THRESHOLD_DAYS.days.ago
    end

    def active?
      success? && !stale?
    end

    def profile_failed?
      failed? && consecutive_failure_count >= FAILED_THRESHOLD
    end

    def pending?
      !not_configured? && last_scan_at.nil?
    end

    def computed_status
      return 'not_configured' if not_configured?
      return 'pending' if pending?
      return 'stale' if stale?
      return 'failed' if profile_failed?
      return 'warning' if warning? || failed?

      'active'
    end
  end
end
