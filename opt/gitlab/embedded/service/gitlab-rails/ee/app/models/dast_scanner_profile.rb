# frozen_string_literal: true

class DastScannerProfile < ::SecApplicationRecord
  include Sanitizable

  belongs_to :project

  validates :project_id, presence: true
  validates :name, length: { maximum: 255 }, uniqueness: { scope: :project_id }, presence: true

  scope :project_id_in, ->(project_ids) { where(project_id: project_ids) }
  scope :with_name, ->(name) { where(name: name) }
  scope :with_project, -> { includes(:project) }

  enum :scan_type, {
    passive: 1,
    active: 2
  }

  sanitizes! :name

  def self.names(scanner_profile_ids)
    find(*scanner_profile_ids).pluck(:name)
  rescue ActiveRecord::RecordNotFound
    []
  end

  def ci_variables(dast_site_profile: nil)
    ::Gitlab::Ci::Variables::Collection.new.tap do |variables|
      variables.append(key: 'DAST_TARGET_AVAILABILITY_TIMEOUT', value: String(target_timeout)) if target_timeout

      variables.append(key: 'DAST_DEBUG', value: String(show_debug_messages))
      variables.append(key: 'DAST_FULL_SCAN_ENABLED', value: String(active?))
      variables.append(key: 'DAST_BROWSER_CRAWL_TIMEOUT', value: "#{String(spider_timeout)}m") if spider_timeout
      variables.append(key: 'DAST_BROWSER_SCAN', value: 'true')

      next unless dast_site_profile&.api?

      if active?
        variables.append(key: 'DAST_API_PROFILE', value: 'Active-Quick')
      else
        variables.append(key: 'DAST_API_PROFILE', value: 'Quick')
      end
    end
  end

  def referenced_in_security_policies
    return [] unless project.all_security_orchestration_policy_configurations.present?

    project
      .all_security_orchestration_policy_configurations
      .map { |configuration| configuration.active_policy_names_with_dast_scanner_profile(name) }
      .inject(&:merge)
      .to_a
  end

  def can_edit_profile?(user)
    can_edit = true
    ::Dast::ProfilesFinder.new(scanner_profile_id: id, with_project: true).execute.find_each do |profile|
      unless Ability.allowed?(user, :update_on_demand_dast_scan, profile)
        can_edit = false
        break
      end
    end

    can_edit
  end
end
