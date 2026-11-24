# frozen_string_literal: true

module Vulnerabilities
  class AscpComponentLink < ::SecApplicationRecord
    self.table_name = 'vulnerability_finding_ascp_component_links'

    belongs_to :vulnerability_finding,
      class_name: 'Vulnerabilities::Finding',
      foreign_key: :vulnerability_occurrence_id,
      inverse_of: :ascp_component_link,
      optional: false
    belongs_to :ascp_component,
      class_name: 'Security::Ascp::Component',
      inverse_of: :vulnerability_finding_ascp_component_links,
      optional: false
    belongs_to :project, optional: false

    validates :vulnerability_occurrence_id, uniqueness: true

    scope :by_finding_ids, ->(finding_ids) { where(vulnerability_occurrence_id: finding_ids) }
    scope :with_component_details, -> { preload(ascp_component: { security_context: :guidelines }) }

    # A component can have one security context per scan, so keep only the newest per finding.
    def self.security_boundaries_by_finding_id(finding_ids)
      contexts = Security::Ascp::SecurityContext.arel_table
      finding_id = arel_table[:vulnerability_occurrence_id]

      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- one row per finding id in the caller's batch
      by_finding_ids(finding_ids)
        .joins(ascp_component: :security_context)
        .order(finding_id, contexts[:id].desc)
        .pluck(Arel.sql("DISTINCT ON (#{quoted_table_name}.vulnerability_occurrence_id) " \
          "#{quoted_table_name}.vulnerability_occurrence_id"), contexts[:security_boundary])
        .to_h
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit
    end
  end
end
