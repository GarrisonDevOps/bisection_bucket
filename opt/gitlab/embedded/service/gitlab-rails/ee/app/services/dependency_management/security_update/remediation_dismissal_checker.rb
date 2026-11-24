# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    # Decides whether a proposed remediation should be skipped because a user already
    # closed an MR for the same vulnerability and we would not be proposing a newer version.
    class RemediationDismissalChecker
      include Gitlab::Utils::StrongMemoize

      # @param project [Project]
      # @param vulnerability [Vulnerability] the vulnerability being remediated
      # @param sbom_occurrence [Sbom::Occurrence, nil] the occurrence the branch was built
      #   from. Must match what the writer recorded, or the row is never found. Nil when
      #   it cannot be resolved or the persisted record path is off, and then no row is read.
      def initialize(project:, vulnerability:, sbom_occurrence:)
        @project = project
        @vulnerability = vulnerability
        @sbom_occurrence = sbom_occurrence
      end

      # @param output [OutputParser::Result] the orchestrator output for the current attempt
      # @return [Boolean]
      def dismissed?(output)
        dismissed_by_record?(output) || dismissed_by_merge_request_history?(output)
      end

      private

      attr_reader :project, :vulnerability, :sbom_occurrence

      # Rows exist only for remediations proposed since the table shipped, so the
      # merge request history below stays until older dismissals have aged out.
      def dismissed_by_record?(output)
        return false unless record&.dismissed?

        candidate = output.version_for(
          JobBuilder.updater_dependency_name(sbom_occurrence.package_manager, record.package_name)
        )
        return false unless candidate

        !version_greater?(candidate, record.target_version)
      end

      def record
        ::DependencyManagement::Remediation.for_occurrence(project, sbom_occurrence)
      end
      strong_memoize_attr :record

      def dismissed_by_merge_request_history?(output)
        return false if dismissed_versions.empty?

        output.dependencies.all? do |dependency|
          dismissed_version = dismissed_versions[dependency.name]
          dismissed_version.present? && !version_greater?(dependency.version, dismissed_version)
        end
      end

      # { dependency_name => highest version a user dismissed }, from MR titles.
      def dismissed_versions
        dismissed_merge_requests.each_with_object({}) do |merge_request, versions|
          match = MergeRequestTitle.parse_single_dependency(merge_request.title)
          next unless match

          name = match[:name]
          version = match[:version]
          versions[name] = version if versions[name].nil? || version_greater?(version, versions[name])
        end
      end
      strong_memoize_attr :dismissed_versions

      def dismissed_merge_requests
        UserClosedRemediationsFinder
          .new(project: project)
          .for_vulnerability(vulnerability)
          .select { |mr| mr.source_branch.start_with?("#{Request::BRANCH_PREFIX}/") }
      end
      strong_memoize_attr :dismissed_merge_requests

      def version_greater?(candidate, other)
        compare_versions(candidate, other) > 0
      end

      def compare_versions(candidate, other)
        # Equal versions need no parsing, so a failure below cannot resurface the dismissed one.
        return 0 if candidate == other

        if package_type.blank?
          log_version_comparison_failure(candidate, other, 'missing package type')
          return 1
        end

        candidate_version = SemverDialects.parse_version(package_type, candidate)
        other_version = SemverDialects.parse_version(package_type, other)
        result = candidate_version <=> other_version

        return result unless result.nil?

        log_version_comparison_failure(candidate, other, 'versions not comparable')
        1
      rescue SemverDialects::Error => error
        log_version_comparison_failure(candidate, other, error.message)
        1
      end

      def log_version_comparison_failure(candidate, other, reason)
        Gitlab::AppLogger.error(
          message: 'DependencyManagement: failed to compare versions for remediation dismissal',
          project_id: project.id,
          package_type: package_type,
          candidate_version: candidate,
          dismissed_version: other,
          error: reason
        )
      end

      def package_type
        ::Enums::Sbom.semver_dialects_purl_type(purl_type)
      end

      def purl_type
        vulnerability.sbom_occurrences.first&.purl_type
      end
      strong_memoize_attr :purl_type
    end
  end
end
