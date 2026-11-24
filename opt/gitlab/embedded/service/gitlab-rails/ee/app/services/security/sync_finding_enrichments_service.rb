# frozen_string_literal: true

module Security
  class SyncFindingEnrichmentsService
    include Security::FindingEnrichmentSync

    BATCH_SIZE = 100

    def initialize(project)
      @project = project
    end

    def execute
      vulnerabilities_scope.each_batch(of: BATCH_SIZE) do |batch|
        findings = Vulnerabilities::Finding.id_in(batch.select(:finding_id)).with_cve_identifiers
        upsert_finding_enrichments(findings, { project_id: project.id })
      end
    end

    private

    attr_reader :project

    def vulnerabilities_scope
      Vulnerability
        .with_project(project.id)
        .present_on_default_branch
    end

    def cve_identifiers_for(finding)
      finding.cve_identifiers
    end
  end
end
