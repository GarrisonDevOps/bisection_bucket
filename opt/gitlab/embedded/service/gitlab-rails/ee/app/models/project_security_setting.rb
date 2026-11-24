# frozen_string_literal: true

class ProjectSecuritySetting < ApplicationRecord
  include Gitlab::InternalEventsTracking

  self.primary_key = :project_id

  belongs_to :project, inverse_of: :security_setting
  validates :license_configuration_source, presence: true

  enum :license_configuration_source, ::Enums::Security.configuration_source_types, suffix: true

  scope :for_projects, ->(project_ids) { where(project_id: project_ids) }

  # saved_change_to_project_id? will return true on creating a new instance as project_id is the primary key
  after_commit -> { schedule_analyzer_status_update_worker_for_type('container_scanning') },
    if: -> { saved_change_to_container_scanning_for_registry_enabled? || saved_change_to_project_id? }

  after_commit -> { schedule_analyzer_status_update_worker_for_type('secret_detection') },
    if: -> { saved_change_to_secret_push_protection_enabled? || saved_change_to_project_id? }

  after_commit :track_validity_checks_change,
    if: -> { validity_checks_disabled? }

  after_commit :track_fast_dependency_paths_change,
    if: -> { fast_dependency_paths_newly_enabled? }

  def set_continuous_vulnerability_scans!(enabled:)
    enabled if update!(continuous_vulnerability_scans_enabled: enabled)
  end

  def set_container_scanning_for_registry!(enabled:)
    enabled if update!(container_scanning_for_registry_enabled: enabled)
  end

  def set_secret_push_protection!(enabled:)
    enabled if update!(secret_push_protection_enabled: enabled)
  end

  def set_cvs_for_container_scanning!(enabled:)
    enabled if update!(cvs_for_container_scanning_enabled: enabled)
  end

  def set_cvs_for_dependency_scanning!(enabled:)
    enabled if update!(cvs_for_dependency_scanning_enabled: enabled)
  end

  def set_license_scanning_for_cyclonedx!(enabled:)
    enabled if update!(license_scanning_for_cyclonedx_enabled: enabled)
  end

  def set_fast_dependency_paths!(enabled:)
    enabled if update!(fast_dependency_paths_enabled: enabled)
  end

  private

  def schedule_analyzer_status_update_worker_for_type(type)
    Security::AnalyzersStatus::SettingChangedUpdateWorker.perform_async([project_id], type)
  end

  def validity_checks_disabled?
    saved_change_to_validity_checks_enabled? &&
      validity_checks_enabled_before_last_save == true && # The old status of Validity Checks enabled
      validity_checks_enabled == false # The new status of Validity Checks enabled
  end

  def track_validity_checks_change
    track_internal_event(
      'disabled_validity_checks',
      project: project
    )
  end

  def fast_dependency_paths_newly_enabled?
    saved_change_to_fast_dependency_paths_enabled?(from: false, to: true)
  end

  def track_fast_dependency_paths_change
    track_internal_event(
      'enabled_fast_dependency_paths',
      project: project,
      namespace: project.namespace
    )
  end
end
