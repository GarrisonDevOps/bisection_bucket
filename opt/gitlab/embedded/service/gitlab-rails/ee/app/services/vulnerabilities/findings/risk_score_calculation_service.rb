# frozen_string_literal: true

module Vulnerabilities
  module Findings
    class RiskScoreCalculationService
      attr_reader :vulnerability_ids

      BATCH_SIZE = 1000

      def self.calculate_for(vulnerability)
        new([vulnerability.id]).execute
      end

      def initialize(vulnerability_ids)
        @vulnerability_ids = vulnerability_ids
      end

      def execute
        findings = Vulnerabilities::Finding.with_cve_enrichments.by_vulnerability(vulnerability_ids)

        findings.each_slice(BATCH_SIZE) do |findings_batch|
          risk_scores = findings_batch.map do |finding|
            {
              finding_id: finding.id,
              project_id: finding.project_id,
              risk_score: Vulnerabilities::RiskScore.from_finding(finding).score
            }
          end

          next unless risk_scores.any?

          Vulnerabilities::FindingRiskScore.upsert_all(
            risk_scores,
            unique_by: :finding_id,
            update_only: [:risk_score]
          )

          log_updates(findings_batch.map(&:vulnerability_id))
        end
        sync_elasticsearch
      end

      private

      def timestamp
        @timestamp ||= Time.current
      end

      def log_updates(ids)
        Gitlab::AppLogger.info(
          class: self.class.name,
          message: "Vulnerability finding risk scores updated",
          vulnerability_ids: ids,
          timestamp: timestamp
        )
      end

      def sync_elasticsearch
        Vulnerabilities::EsHelper.sync_elasticsearch(vulnerability_ids)
      end
    end
  end
end
