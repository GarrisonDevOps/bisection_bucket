# frozen_string_literal: true

module PackageMetadata
  class CveEnrichment < ApplicationRecord
    self.table_name = 'pm_cve_enrichment'

    # The 15 (total 24) character limit is arbitrary. CVE IDs are not limited
    # but we do not expect them to exceed this limit.
    # See https://cve.mitre.org/cve/identifiers/syntaxchange.html
    CVE_REGEX = /\ACVE-\d{4}-\d{4,15}\z/

    has_many :identifiers,
      class_name: 'Vulnerabilities::Identifier',
      primary_key: :name,
      foreign_key: :cve,
      inverse_of: :cve_enrichment

    has_many :finding_enrichments,
      class_name: 'Security::FindingEnrichment',
      inverse_of: :cve_enrichment

    has_many :security_findings,
      through: :finding_enrichments,
      source: :security_finding,
      class_name: 'Security::Finding'

    validates :cve, presence: true, format: { with: CVE_REGEX }
    validates :epss_score, presence: true
    validates :is_known_exploit, inclusion: { in: [true, false] }

    scope :by_cves, ->(cves) { where(cve: cves) }
    scope :updated_after, ->(time) { where(arel_table[:updated_at].gt(time)).order(:updated_at, :id) }

    def self.pluck_id(limit = MAX_PLUCK)
      limit(limit).ids
    end

    # rubocop:disable Layout/ClassStructure -- This is included at the bottom of the model definition because
    # BulkInsertSafe complains about the autosave callbacks generated
    # for the `has_many` associations otherwise.
    include BulkInsertSafe

    # rubocop:enable Layout/ClassStructure
  end
end
