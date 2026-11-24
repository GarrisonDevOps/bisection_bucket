# frozen_string_literal: true

module Vulnerabilities
  module DetectionTransitions
    class InsertService
      MAX_BATCH_SIZE = 1000

      def initialize(vulnerability_findings, detected:)
        @vulnerability_findings = Array(vulnerability_findings)
        @detected = detected
        @timestamp = Time.current
      end

      def execute
        return if vulnerability_findings.empty? || detected.nil?

        vulnerability_findings.each_slice(MAX_BATCH_SIZE) do |batch|
          records = build_detection_transition_records(batch)

          next if records.empty?

          insert_records(records)

          log_updates(batch.map(&:id))
        end

        sync_elasticsearch(vulnerability_findings.map(&:vulnerability_id))

        ServiceResponse.success
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, vulnerability_finding_ids: vulnerability_findings.map(&:id))
        ServiceResponse.error(message: e.message)
      end

      private

      attr_reader :vulnerability_findings, :detected, :timestamp

      def build_detection_transition_records(findings)
        findings.map do |finding|
          ::Vulnerabilities::DetectionTransition.new(
            vulnerability_occurrence_id: finding.id,
            project_id: finding.project_id,
            detected: detected,
            created_at: timestamp,
            updated_at: timestamp
          )
        end
      end

      def insert_records(records)
        ::Vulnerabilities::DetectionTransition.bulk_insert!(records)
      end

      def log_updates(ids)
        Gitlab::AppLogger.info(
          class: self.class.name,
          message: "Vulnerability finding detection transitions inserted",
          finding_ids: ids,
          timestamp: timestamp
        )
      end

      def sync_elasticsearch(vulnerability_ids)
        Vulnerabilities::EsHelper.sync_elasticsearch(vulnerability_ids)
      end
    end
  end
end
