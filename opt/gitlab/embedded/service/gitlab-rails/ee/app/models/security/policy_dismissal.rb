# frozen_string_literal: true

module Security
  class PolicyDismissal < ApplicationRecord
    self.table_name = 'security_policy_dismissals'
    DISMISSAL_TYPES = {
      policy_false_positive: 0,
      scanner_false_positive: 1,
      emergency_hot_fix: 2,
      other: 3
    }.freeze

    def self.dismissal_type_name(type_value)
      DISMISSAL_TYPES.key(type_value)
    end

    belongs_to :project, class_name: 'Project', optional: false
    belongs_to :merge_request, class_name: 'MergeRequest', optional: false
    belongs_to :security_policy, class_name: 'Security::Policy', optional: true
    belongs_to :user, class_name: 'User', optional: true

    validates :merge_request_id, uniqueness: { scope: :security_policy_id }
    validates :comment, length: { maximum: 255 }, allow_nil: true
    validate  :dismissal_types_are_valid
    validates :licenses, json_schema: { filename: 'policy_dismissal_licenses', size_limit: 64.kilobytes },
      allow_blank: true
    validates :license_occurrence_uuids, length: { maximum: 1000 }

    scope :for_projects, ->(project_ids) { where(project_id: project_ids) }
    scope :for_security_findings_uuids, ->(security_findings_uuids) do
      where("security_findings_uuids && ARRAY[?]::text[]", security_findings_uuids)
    end
    scope :including_merge_request_and_user, -> { includes(:user, :merge_request) }
    scope :including_project, -> { includes(:project) }
    scope :including_security_policy, -> { includes(:security_policy) }
    scope :for_merge_requests, ->(merge_request_ids) { where(merge_request_id: merge_request_ids) }
    scope :for_license_occurrence_uuids, ->(license_occurrence_uuids) do
      where("license_occurrence_uuids && ARRAY[?]::text[]", license_occurrence_uuids).preserved
    end

    enum :status, { open: 0, preserved: 1 }

    def self.pluck_security_findings_uuid(limit = MAX_PLUCK)
      limit(limit).pluck(Arel.sql('DISTINCT unnest(security_findings_uuids)'))
    end

    def self.pluck_license_occurrence_uuid(limit = MAX_PLUCK)
      limit(limit).pluck(Arel.sql('DISTINCT unnest(license_occurrence_uuids)'))
    end

    # A dismissal matches on one overlapping uuid but can carry 1000, so
    # .pluck_license_occurrence_uuid's MAX_PLUCK cap can drop uuids the caller asked about.
    # Intersecting in Postgres instead bounds the result by the size of the argument.
    def self.dismissed_license_occurrence_uuids(uuids)
      return [] if uuids.blank?

      for_license_occurrence_uuids(uuids)
        .joins('CROSS JOIN LATERAL unnest(security_policy_dismissals.license_occurrence_uuids) AS dismissed(uuid)')
        .where('dismissed.uuid = ANY (ARRAY[?]::text[])', uuids)
        .distinct
        # Cannot fire: DISTINCT over rows already filtered to `uuids` yields at most
        # uuids.uniq.size. Present to satisfy Database/AvoidUsingPluckWithoutLimit.
        .limit(uuids.size)
        .pluck(Arel.sql('dismissed.uuid'))
    end

    def preserve!
      return destroy! unless applicable_for_all_violations? || for_any_merge_request_violation?

      update!(status: :preserved)

      event = Security::PolicyDismissalPreservedEvent.new(data: {
        security_policy_dismissal_id: id
      })
      ::Gitlab::EventStore.publish(event)
    end

    def applicable_for_findings?(finding_uuids)
      return false if security_findings_uuids.nil?

      finding_uuids.to_set.subset?(security_findings_uuids.to_set)
    end

    def applicable_for_licenses?(violation_licenses)
      all_violated_components = violation_licenses.values.flatten.compact.to_set
      dismissed_components = licenses.values.flatten.to_set

      all_violated_components.subset?(dismissed_components)
    end

    def applicable_for_all_violations?
      applicable_for_findings?(mr_violation_finding_uuids) && applicable_for_licenses?(mr_violation_licenses)
    end

    def license_names
      licenses.keys
    end

    def components(license_name)
      licenses.fetch(license_name, [])
    end

    private

    def for_any_merge_request_violation?
      security_findings_uuids.blank? &&
        licenses.blank? &&
        mr_violation_finding_uuids.empty? &&
        mr_violation_licenses.empty?
    end

    def scan_result_policy_violations
      merge_request.scan_result_policy_violations
                   .joins(:security_policy)
                   .where(security_policies: { id: security_policy_id })
    end

    def mr_violation_finding_uuids
      scan_result_policy_violations.flat_map(&:finding_uuids).uniq
    end

    def mr_violation_licenses
      scan_result_policy_violations.flat_map(&:licenses).reduce({}) do |acc, license_hash|
        acc.deep_merge(license_hash) { |_key, old_val, new_val| (Array(old_val) + Array(new_val)).uniq }
      end
    end

    def dismissal_types_are_valid
      invalid_values = Array(dismissal_types) - DISMISSAL_TYPES.values
      return if dismissal_types.present? && invalid_values.blank?

      errors.add(:dismissal_types, "must be an array with allowed values: #{DISMISSAL_TYPES.values.join(', ')}")
    end
  end
end
