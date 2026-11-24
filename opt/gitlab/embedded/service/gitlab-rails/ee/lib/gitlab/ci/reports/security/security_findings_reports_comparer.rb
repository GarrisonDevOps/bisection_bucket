# frozen_string_literal: true

module Gitlab
  module Ci
    module Reports
      module Security
        class SecurityFindingsReportsComparer
          include Gitlab::Utils::StrongMemoize

          attr_reader :project, :params, :added_findings, :fixed_findings

          ACCEPTABLE_REPORT_AGE = 1.week
          MAX_FINDINGS_COUNT = 25
          MAX_COMPARED_FINDINGS = 1_000
          LARGER_MAX_COMPARED_FINDINGS = 10_000
          VULNERABILITY_FILTER_METRIC_KEY = :vulnerability_report_branch_comparison

          def initialize(project, params)
            @project = project
            @params = params

            @added_findings = []
            @fixed_findings = []
            calculate_changes
          end

          def base_report
            params[:base_report]
          end

          def head_report
            params[:head_report]
          end

          def base_report_created_at
            base_report.created_at
          end

          def head_report_created_at
            head_report.created_at
          end

          def base_report_out_of_date
            return false unless base_report.created_at

            base_report.created_at.before?(ACCEPTABLE_REPORT_AGE.ago)
          end

          # rubocop:disable CodeReuse/ActiveRecord -- pluck method requires this
          def undismissed_on_default_branch(findings)
            uuids = findings.map(&:uuid)

            query = Vulnerability
              .present_on_default_branch.with_findings_by_uuid_and_state(uuids, :dismissed)

            dismissed_uuids = ::Gitlab::Metrics.measure(VULNERABILITY_FILTER_METRIC_KEY) do
              query.pluck('findings.uuid')
            end.to_set

            findings.reject { |f| dismissed_uuids.include?(f.uuid) }
          end

          def process_findings(findings)
            # Comparison runs over up to MAX_COMPARED_FINDINGS (or LARGER_MAX_COMPARED_FINDINGS) findings
            # per scan and severity, but we cap the result here until we can properly paginate.
            # See https://gitlab.com/groups/gitlab-org/-/work_items/20760
            undismissed_findings = []

            findings.each_slice(MAX_FINDINGS_COUNT) do |slice|
              undismissed_findings.concat(undismissed_on_default_branch(slice))
              break if undismissed_findings.size >= MAX_FINDINGS_COUNT
            end

            undismissed_findings.first(MAX_FINDINGS_COUNT)
          end
          # rubocop:enable CodeReuse/ActiveRecord

          def added
            hydrate(process_findings(added_findings))
          end
          strong_memoize_attr :added

          def fixed
            hydrate(process_findings(fixed_findings))
          end
          strong_memoize_attr :fixed

          def errors
            []
          end
          strong_memoize_attr :errors

          def warnings
            []
          end
          strong_memoize_attr :warnings

          private

          def lean_findings?
            params[:lean_findings].present?
          end

          # Lean findings carry the comparison columns only (see Security::FindingsFinder `lean`).
          # Reload the capped result with everything the serializer and policy checks need.
          def hydrate(findings)
            return findings if findings.empty? || !lean_findings?

            records = ::Security::Finding
              .by_partition_number(findings.map(&:partition_number).uniq)
              .id_in(findings.map(&:id))
              .preload_report_associations
              .with_api_scopes
              .index_by(&:id)

            hydrated = findings.filter_map { |finding| records[finding.id] }
            ::Security::Finding.preload_auto_dismissal_checks!(project, hydrated)
            ::Security::Finding.preload_severity_override_checks!(project, hydrated)

            hydrated
          end

          def calculate_changes
            base_findings = base_report.findings
            head_findings = head_report.findings

            # For full scan comparisons where the head pipeline includes partial scans,
            # filter out base findings from scanners that also run as partial scans
            # (identified by partial_scan_scanner_ids). This prevents vulnerabilities
            # detected by those scanners in the base pipeline from incorrectly appearing
            # as "fixed" in the full scan tab, since they're already handled in their
            # respective partial scan comparisons.
            if params[:scan_mode] == 'full' && params[:partial_scan_scanner_ids].present?
              base_findings = base_findings.reject do |finding|
                params[:partial_scan_scanner_ids].include?(partial_scan_scanner_key(finding))
              end
            end

            base_findings_uuids_set = base_findings.map(&:policy_comparison_uuid).to_set

            @added_findings = head_findings.reject { |f| base_findings_uuids_set.include?(f.policy_comparison_uuid) }

            # Partial scans only have coverage of changed files are
            # unlikely to find all existing vulnerabilities.
            # We hide the fixed results since they will often be wrong.
            return if params[:scan_mode] == 'partial'
            return if lean_findings? && comparison_requires_manual_resolution?

            head_findings_uuids_set = head_findings.map(&:policy_comparison_uuid).to_set

            @fixed_findings = base_findings.reject do |finding|
              next true if !lean_findings? && finding.requires_manual_resolution?

              head_findings_uuids_set.include?(finding.policy_comparison_uuid)
            end
          end

          # Lean findings don't have the scanner loaded, so they match on `scanner_id`
          # against the project's scanner records instead of the report's external id.
          def partial_scan_scanner_key(finding)
            lean_findings? ? finding.scanner_id : finding.scanner.external_id
          end

          # Lean findings don't have the scan loaded. All findings in a comparison share
          # the report type, so the per-finding check moves up to the comparison.
          def comparison_requires_manual_resolution?
            ::Vulnerability::REPORT_TYPES_REQUIRING_MANUAL_RESOLUTION.include?(params[:report_type].to_s)
          end
        end
      end
    end
  end
end
