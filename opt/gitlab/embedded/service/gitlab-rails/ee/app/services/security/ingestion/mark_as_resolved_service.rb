# frozen_string_literal: true

module Security
  module Ingestion
    # This service class takes the IDs of recently ingested
    # vulnerabilities for a project which had been previously
    # detected by the same scanner, and marks them as resolved
    # on the default branch if they were not detected again.
    # The report_type parameter is optional and currently only used
    # in the context of the GitLab Sbom Vulnerability Scanner.
    # These scans create different types of vulnerabilities and
    # this service must take this criteria into account to avoid
    # marking vulnerabilities of other types as no longer detected
    # in some scenarios.
    class MarkAsResolvedService
      include Gitlab::InternalEventsTracking
      include Gitlab::Utils::StrongMemoize

      CVS_SCANNER_EXTERNAL_ID = 'gitlab-sbom-vulnerability-scanner'
      CS_SCANNERS_EXTERNAL_IDS = %w[trivy].freeze
      DS_SCANNERS_EXTERNAL_IDS = %w[gemnasium gemnasium-maven gemnasium-python].freeze

      BATCH_SIZE = 1000
      AUTO_RESOLVE_LIMIT = 1000

      def self.execute(...)
        new(...).execute
      end

      def initialize(
        pipeline, scanner, ingested_ids, tracked_context, report_type = nil, full_secret_detection_scan: false
      )
        @pipeline = pipeline
        @scanner = scanner
        @ingested_ids = ingested_ids
        @tracked_context = tracked_context
        @report_type = report_type
        @full_secret_detection_scan = full_secret_detection_scan
        @auto_resolved_count = 0
        @requires_statistics_refresh = false
      end

      def execute
        return unless scanner

        vulnerabilities_to_process = vulnerability_reads.by_scanner(scanner)
        # The report_type is only used with the GitLab Sbom Vulnerability Scanner. See https://gitlab.com/gitlab-org/gitlab/-/issues/516232
        vulnerabilities_to_process = vulnerabilities_to_process.with_report_types(report_type) if report_type.present?
        vulnerabilities_to_process.each_batch(of: BATCH_SIZE) do |batch|
          if Security::VAC.disabled?(pipeline.project)
            process_batch(batch)
          else
            process_batch(batch.by_tracked_context(tracked_context))
          end
        end

        if scanner_for_container_scanning?
          process_existing_cvs_vulnerabilities_for_container_scanning
        elsif scanner_for_dependency_scanning?
          process_existing_cvs_vulnerabilities_for_dependency_scanning
        end

        update_vulnerability_statistics
      end

      private

      attr_accessor :auto_resolved_count
      attr_reader :pipeline, :scanner, :ingested_ids, :report_type, :tracked_context, :full_secret_detection_scan

      delegate :project, to: :scanner, private: true
      delegate :vulnerability_reads, to: :project, private: true

      def process_batch(batch)
        (batch.pluck_primary_key - ingested_ids).then do |missing_ids|
          next if missing_ids.blank?

          still_detected, no_longer_detected = Vulnerability
                                                 .id_in(missing_ids)
                                                 .not_requiring_manual_resolution
                                                 # rubocop:disable CodeReuse/ActiveRecord -- context-specific
                                                 # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- Batch size of 1000
                                                 .pluck(:id, :resolved_on_default_branch)
                                                 # rubocop:enable CodeReuse/ActiveRecord
                                                 # rubocop:enable Database/AvoidUsingPluckWithoutLimit
                                                 .partition { |_id, resolved| resolved }
                                                 .map { |group| group.map(&:first) }

          mark_as_no_longer_detected(no_longer_detected) if no_longer_detected.present?
          auto_resolve(no_longer_detected + still_detected)

          create_representation_information(no_longer_detected + removed_secret_detection_ids(missing_ids))
        end
      end

      def mark_as_no_longer_detected(vulnerability_ids)
        vulnerabilities_relation = Vulnerability.id_in(vulnerability_ids)

        ::Vulnerabilities::BulkEsOperationService.new(vulnerabilities_relation).execute do |relation|
          relation.update_all(resolved_on_default_branch: true, updated_at: Time.current)
          create_detection_transitions(vulnerability_ids)
        end

        Vulnerabilities::Reads::UpsertService.new(
          vulnerabilities_relation,
          { resolved_on_default_branch: true },
          projects: project
        ).execute

        track_no_longer_detected_vulnerabilities(vulnerability_ids.count)

        @requires_statistics_refresh = true
      end

      def update_vulnerability_statistics
        return unless @requires_statistics_refresh

        ::Vulnerabilities::Statistics::AdjustmentWorker.perform_async([project.id])
      end

      def create_detection_transitions(vulnerability_ids)
        findings = Vulnerabilities::Finding.by_vulnerability(vulnerability_ids)
        ::Vulnerabilities::DetectionTransitions::InsertService.new(findings, detected: false).execute
      end

      def auto_resolve(no_longer_detected_vulnerabilities)
        budget = AUTO_RESOLVE_LIMIT - auto_resolved_count
        return unless budget > 0

        result = Vulnerabilities::AutoResolveService
                   .new(pipeline, no_longer_detected_vulnerabilities, budget)
                   .execute

        if result.success?
          @auto_resolved_count += result.payload[:count]
        else
          track_auto_resolve_error(result)
        end
      end

      # A secret missing from a scan of only some commits (for example a push's commit range) may
      # still be in the code, and flagging it as removed would redact its location.
      def removed_secret_detection_ids(missing_ids)
        return [] unless full_secret_detection_scan

        Vulnerability.secret_detection.id_in(missing_ids)
      end

      def create_representation_information(vulnerability_ids)
        return if vulnerability_ids.blank?

        vulnerabilities = Vulnerability.id_in(vulnerability_ids)
        CreateVulnerabilityRepresentationInformation.execute(pipeline, vulnerabilities)
      end

      def process_existing_cvs_vulnerabilities_for_container_scanning
        vulnerability_reads
          .by_scanner_ids(cvs_scanner_id)
          .with_report_types(:container_scanning)
          .each_batch { |batch| process_batch(batch) }
      end

      def process_existing_cvs_vulnerabilities_for_dependency_scanning
        vulnerability_reads
          .by_scanner_ids(cvs_scanner_id)
          .with_report_types(:dependency_scanning)
          .each_batch { |batch| process_batch(batch) }
      end

      def cvs_scanner_id
        ::Vulnerabilities::Scanner.for_projects(project.id)
          .with_external_id(CVS_SCANNER_EXTERNAL_ID)
          .pluck_primary_key
      end

      def scanner_for_container_scanning?
        scanner.external_id.in?(CS_SCANNERS_EXTERNAL_IDS)
      end

      def scanner_for_dependency_scanning?
        scanner.external_id.in?(DS_SCANNERS_EXTERNAL_IDS)
      end

      def track_auto_resolve_error(result)
        # Log only once per pipeline
        strong_memoize(:track_auto_resolve_error) do
          exception = result.payload[:exception]

          if exception
            Gitlab::ErrorTracking.track_exception(exception)
          else
            Gitlab::AppJsonLogger.error(
              class: self.class.name,
              message: result.message,
              reason: result.reason
            )
          end
        end
      end

      def track_no_longer_detected_vulnerabilities(count)
        Gitlab::InternalEvents.with_batched_redis_writes do
          count.times do
            track_internal_event(
              'vulnerability_no_longer_detected_on_default_branch',
              project: project
            )
          end
        end
      end
    end
  end
end
