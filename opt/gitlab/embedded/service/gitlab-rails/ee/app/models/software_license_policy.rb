# frozen_string_literal: true

# This class represents a software license policy. Which means the fact that the user
# approves or not of the use of a certain software license in their project.
# For use in the License Management feature.
class SoftwareLicensePolicy < ApplicationRecord
  include Presentable
  include FromUnion

  # Only allows modification of the approval status
  FORM_EDITABLE = %i[approval_status].freeze

  belongs_to :project, inverse_of: :software_license_policies
  belongs_to :custom_software_license, class_name: 'Security::CustomSoftwareLicense'
  belongs_to :scan_result_policy_read,
    class_name: 'Security::ScanResultPolicyRead',
    foreign_key: 'scan_result_policy_id',
    optional: true

  belongs_to :approval_policy_rule, class_name: 'Security::ApprovalPolicyRule', optional: true

  attr_readonly :custom_software_license

  enum :classification, {
    denied: 0,
    allowed: 1
  }
  validates_presence_of :project
  validates :classification, presence: true

  validates :custom_software_license, presence: true, unless: :software_license_spdx_identifier
  validates :software_license_spdx_identifier, presence: true, unless: :custom_software_license

  validates :custom_software_license, uniqueness: { scope: [:project_id, :scan_result_policy_id] }, allow_blank: true
  validates :software_license_spdx_identifier, length: { maximum: 255 }

  scope :for_project, ->(project) { where(project: project) }
  scope :for_scan_result_policy_read, ->(scan_result_policy_id) { where(scan_result_policy_id: scan_result_policy_id) }
  scope :for_approval_policy_rule,
    ->(approval_policy_rule_id) { where(approval_policy_rule_id: approval_policy_rule_id) }
  scope :including_custom_license, -> { includes(:custom_software_license) }
  scope :including_scan_result_policy_read, -> { includes(:scan_result_policy_read) }
  scope :including_approval_policy_rule, -> { includes(:approval_policy_rule) }
  scope :unreachable_limit, -> { limit(1_000) }

  # Allow-list policies only: deny-list `licenses` rules can also store match_on_inclusion_license: false.
  scope :exclusion_allowed, -> do
    allowed
      .joins(:scan_result_policy_read)
      .where(scan_result_policy_read: { match_on_inclusion_license: false })
  end

  scope :by_spdx, ->(spdx_identifier) do
    where(software_license_spdx_identifier: spdx_identifier)
  end

  def self.approval_status_values
    %w[allowed denied]
  end

  def self.latest_active_licenses
    Gitlab::SPDX::Catalogue.latest_active_licenses
  end

  def self.latest_active_licenses_by_name(license_names)
    latest_active_licenses.select do |license|
      license.name.downcase.in?(license_names)
    end
  end

  def self.latest_active_licenses_by_spdx(spdx_identifier)
    latest_active_licenses.select { |license| license.id == spdx_identifier }
  end

  def approval_status
    classification
  end

  def name
    if software_license_spdx_identifier
      self.class.latest_active_licenses_by_spdx(software_license_spdx_identifier)&.first&.name
    elsif custom_software_license
      custom_software_license&.name
    end
  end

  def spdx_identifier
    software_license_spdx_identifier
  end
end
