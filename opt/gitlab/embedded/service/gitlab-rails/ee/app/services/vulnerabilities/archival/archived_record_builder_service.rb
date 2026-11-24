# frozen_string_literal: true

module Vulnerabilities
  module Archival
    class ArchivedRecordBuilderService
      def self.execute(...)
        new(...).execute
      end

      def initialize(vulnerability_archive, vulnerability)
        @vulnerability_archive = vulnerability_archive
        @vulnerability = vulnerability
        @now = Time.zone.now
      end

      def execute
        Vulnerabilities::ArchivedRecord.new(
          project: project,
          archive: vulnerability_archive,
          vulnerability_identifier: vulnerability.id,
          data: archive_data,
          created_at: now,
          updated_at: now
        )
      end

      private

      attr_reader :vulnerability_archive, :vulnerability, :now

      delegate :project, to: :vulnerability_archive, private: true
      delegate :finding, to: :vulnerability, private: true
      delegate :vulnerability_read, to: :vulnerability, private: true

      def archive_data
        {
          report_type: vulnerability.report_type,
          scanner: finding&.scanner&.name.to_s,
          state: vulnerability.state,
          severity: vulnerability.severity,
          title: vulnerability.title,
          description: finding&.description.to_s,
          cve_value: vulnerability.cve_value,
          cwe_value: vulnerability.cwe_value,
          other_identifiers: vulnerability.other_identifier_values.to_a,
          created_at: vulnerability.created_at.to_s,
          location: vulnerability.location,
          resolved_on_default_branch: vulnerability.resolved_on_default_branch,
          notes_summary: vulnerability.notes_summary,
          full_path: vulnerability.full_path,
          cvss: vulnerability.cvss,
          dismissal_reason: vulnerability_read&.dismissal_reason
        }.merge!(
          dismissal_information,
          confirm_information,
          resolve_information,
          related_issue_information,
          related_mr_information
        )
      end

      def dismissal_information
        return {} unless vulnerability.dismissed?

        {
          dismissed_at: vulnerability.dismissed_at.to_s,
          dismissed_by: vulnerability.dismissed_by&.username
        }
      end

      def confirm_information
        return {} unless vulnerability.confirmed?

        {
          confirmed_at: vulnerability.confirmed_at.to_s,
          confirmed_by: vulnerability.confirmed_by&.username
        }
      end

      def resolve_information
        return {} unless vulnerability.resolved?

        {
          resolved_at: vulnerability.resolved_at.to_s,
          resolved_by: vulnerability.resolved_by&.username
        }
      end

      def related_issue_information
        return {} unless vulnerability.issue_links.present?

        issue_links_data = vulnerability.issue_links.map do |issue_link|
          {
            type: issue_link.link_type,
            id: issue_link.issue_id
          }
        end

        {
          related_issues: issue_links_data
        }
      end

      def related_mr_information
        return {} unless vulnerability.merge_requests.present?

        {
          related_mrs: vulnerability.merge_requests.map(&:id)
        }
      end
    end
  end
end
