# frozen_string_literal: true

module Security
  class FindingEnrichment < SecApplicationRecord
    self.table_name = 'security_finding_enrichments'

    belongs_to :project, class_name: 'Project', optional: false
    belongs_to :security_finding,
      class_name: 'Security::Finding',
      inverse_of: :finding_enrichments,
      primary_key: 'uuid',
      foreign_key: 'finding_uuid',
      optional: false

    belongs_to :vulnerability_finding,
      class_name: 'Vulnerabilities::Finding',
      inverse_of: :security_finding_enrichments,
      primary_key: 'uuid',
      foreign_key: 'finding_uuid',
      optional: true

    belongs_to :cve_enrichment,
      class_name: 'PackageMetadata::CveEnrichment',
      inverse_of: :finding_enrichments,
      optional: true

    belongs_to :vulnerability,
      class_name: '::Vulnerability',
      inverse_of: :security_finding_enrichments,
      optional: true

    validates :finding_uuid, uniqueness: { scope: :cve }
    validates :cve, presence: true, format: { with: PackageMetadata::CveEnrichment::CVE_REGEX }

    scope :with_known_exploited, ->(known_exploited) { where(is_known_exploit: known_exploited) }

    scope :with_epss_score, ->(operator, value) do
      break none unless operator && value

      epss_score = arel_table[:epss_score]
      condition = case operator.to_sym
                  when :greater_than then epss_score.gt(value)
                  when :less_than then epss_score.lt(value)
                  else
                    raise ArgumentError, "Unsupported operator: #{operator}"
                  end

      where(condition)
    end

    scope :by_cve_enrichment_id, ->(cve_enrichment_ids) { where(cve_enrichment_id: cve_enrichment_ids) }

    scope :with_enrichment_filters, ->(known_exploited: nil, epss_operator: nil, epss_value: nil) do
      filter_by_known_exploited = known_exploited == true
      filter_by_epss_score = epss_operator && epss_value

      return none unless filter_by_known_exploited || filter_by_epss_score

      scope = all
      scope = scope.with_known_exploited(known_exploited) if filter_by_known_exploited
      scope = scope.with_epss_score(epss_operator, epss_value) if filter_by_epss_score
      scope
    end

    scope :stale, -> { where(created_at: ...Security::Scan.stale_after.ago, vulnerability_id: nil) }

    scope :ordered_by_created_at_and_id, -> { order(:created_at, :id) }

    scope :including_project, -> { includes(:project) }
    scope :for_finding_uuids, ->(uuids) { where(finding_uuid: uuids) }
  end
end
