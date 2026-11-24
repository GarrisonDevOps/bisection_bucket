# frozen_string_literal: true

module Security
  module Ingestion
    # Service for starting the ingestion of the security reports
    # into the database.
    class IngestReportsService
      include Gitlab::Utils::StrongMemoize
      include Gitlab::Loggable
      include Gitlab::InternalEventsTracking

      def self.execute(pipeline)
        new(pipeline).execute
      end

      def initialize(pipeline)
        @pipeline = pipeline
        @original_archived_value = project.archived
        @original_traversal_ids_value = project.namespace.traversal_ids
      end

      def execute
        store_reports
        log_ingestion
        mark_resolved_vulnerabilities
        auto_dismiss_vulnerabilities
        auto_severity_override_vulnerabilities
        mark_project_as_vulnerable!
        set_latest_pipeline!
        schedule_mark_dropped_vulnerabilities
        sync_findings_to_approval_rules
        schedule_sbom_records
        schedule_updating_archived_status_if_needed
        schedule_updating_traversal_ids_if_needed
        schedule_consistency_checks
      end

      private

      attr_reader :pipeline, :original_archived_value, :original_traversal_ids_value

      delegate :project, to: :pipeline, private: true

      # Reports are only ingested for the default branch or for a tracked non-default context,
      # so `is_default` tells us which of the two the ingestion was for.
      def log_ingestion
        Gitlab::AppJsonLogger.info(
          build_structured_payload_labkit(
            Labkit::Fields::LOG_MESSAGE => 'Ingesting security reports',
            Labkit::Fields::GL_PROJECT_ID => project.id,
            Labkit::Fields::GL_PIPELINE_ID => pipeline.id,
            context_name: tracked_context.context_name,
            context_type: tracked_context.context_type,
            is_default: tracked_context.is_default?
          )
        )
        track_internal_event(
          "ingest_security_reports",
          namespace: project.namespace,
          project: project,
          additional_properties: {
            label: tracked_context.is_default? ? 'default_branch' : 'non_default_branch'
          }
        )
      end

      def store_reports
        latest_security_scans.flat_map do |scan|
          ingest(scan).then { |ingested_ids| collect_ingested_ids_for(scan, ingested_ids) }
        end
      end

      def collect_ingested_ids_for(scan, ingested_ids)
        key = { scanner: scan.scanner, report_type: scan.scan_type }
        full_secret_detection_scan_keys << key if scan.secret_detection? && scan.full_secret_detection_scan?
        ingested_ids_by_scanner_and_type[key] += ingested_ids
      end

      def full_secret_detection_scan_keys
        @full_secret_detection_scan_keys ||= Set.new
      end

      def latest_security_scans
        @latest_security_scans ||= pipeline.root_ancestor
          .self_and_descendant_security_scans
          .without_errors
          .latest_successful
      end

      def ingested_ids_by_scanner_and_type
        @ingested_ids_by_scanner_and_type ||= Hash.new { [] }
      end

      def ingest(security_scan)
        IngestReportService.execute(security_scan)
      end

      def mark_project_as_vulnerable!
        project.project_setting.mark_as_vulnerable! if ingested_vulnerabilities?
      end

      def ingested_vulnerabilities?
        ingested_ids_by_scanner_and_type.values.any?(&:present?)
      end

      def set_latest_pipeline!
        Vulnerabilities::Statistic.set_latest_pipeline_with(pipeline)
      end

      def tracked_context
        result = ::Security::ProjectTrackedContexts::FindOrCreateService.from_pipeline(pipeline).execute!

        raise ArgumentError, result.message unless result.success?

        result.payload[:tracked_context]
      end
      strong_memoize_attr :tracked_context

      def mark_resolved_vulnerabilities
        ingested_ids_by_scanner_and_type.each do |key, ingested_ids|
          MarkAsResolvedService.execute(
            pipeline, key[:scanner], ingested_ids, tracked_context, key[:report_type],
            full_secret_detection_scan: full_secret_detection_scan_keys.include?(key)
          )
        end
      end

      def auto_dismiss_vulnerabilities
        ingested_ids_by_scanner_and_type.each do |key, ingested_ids|
          next if ingested_ids.empty?

          result = Vulnerabilities::AutoDismissService.new(pipeline, ingested_ids).execute

          if result.error?
            Gitlab::AppJsonLogger.error(
              message: "Failed to auto-dismiss vulnerabilities",
              project_id: project.id,
              pipeline_id: pipeline.id,
              scanner: key[:scanner],
              error: result.message,
              reason: result.reason
            )
          elsif result.payload[:count] > 0
            Gitlab::AppJsonLogger.debug(
              message: "Auto-dismissed vulnerabilities",
              project_id: project.id,
              pipeline_id: pipeline.id,
              scanner: key[:scanner],
              count: result.payload[:count]
            )
          end
        end
      rescue StandardError => e
        Gitlab::AppJsonLogger.error(
          message: "Exception during auto-dismiss vulnerabilities",
          project_id: project.id,
          pipeline_id: pipeline.id,
          error: e.message
        )
        Gitlab::ErrorTracking.track_exception(e)
      end

      def auto_severity_override_vulnerabilities
        ingested_ids_by_scanner_and_type.each do |key, ingested_ids|
          next if ingested_ids.empty?

          result = Vulnerabilities::AutoSeverityOverrideService.new(pipeline, ingested_ids).execute

          if result.error?
            Gitlab::AppJsonLogger.error(
              message: "Failed to auto-override vulnerability severities",
              project_id: project.id,
              pipeline_id: pipeline.id,
              scanner: key[:scanner],
              error: result.message,
              reason: result.reason
            )
          elsif result.payload[:count] > 0
            Gitlab::AppJsonLogger.debug(
              message: "Auto-overrode vulnerability severities",
              project_id: project.id,
              pipeline_id: pipeline.id,
              scanner: key[:scanner],
              count: result.payload[:count]
            )
          end
        end
      rescue StandardError => e
        Gitlab::AppJsonLogger.error(
          message: "Exception during auto-severity-override",
          project_id: project.id,
          pipeline_id: pipeline.id,
          error: e.message
        )
        Gitlab::ErrorTracking.track_exception(e)
      end

      def schedule_mark_dropped_vulnerabilities
        primary_identifiers_by_scan_type.each do |scan_type, identifiers|
          ScheduleMarkDroppedAsResolvedService.execute(pipeline.project_id, scan_type, identifiers)
        end
      end

      def sync_findings_to_approval_rules
        return unless ::Security::PolicyAvailability.any_available?(project)

        Security::ScanResultPolicies::SyncFindingsToApprovalRulesWorker.perform_async(pipeline.id)
      end

      def primary_identifiers_by_scan_type
        latest_security_scans.group_by(&:scan_type)
                             .transform_values { |scans| scans.flat_map(&:report_primary_identifiers).compact }
      end

      def schedule_sbom_records
        ::Sbom::ScheduleIngestReportsService.new(pipeline).execute
      end

      def schedule_updating_archived_status_if_needed
        return unless archived_value_changed?

        Vulnerabilities::UpdateArchivedAttributeOfVulnerabilityReadsWorker.perform_async(project.id)
      end

      def schedule_updating_traversal_ids_if_needed
        return unless traversal_ids_value_changed?

        Vulnerabilities::UpdateNamespaceIdsOfVulnerabilityReadsWorker.perform_async(project.id)
      end

      def schedule_consistency_checks
        Vulnerabilities::ConsistencyChecks.ensure_consistency_on_project!(project)
      end

      def archived_value_changed?
        reloaded_project.archived != original_archived_value
      end

      def traversal_ids_value_changed?
        reloaded_project.namespace.traversal_ids != original_traversal_ids_value
      end

      def reloaded_project
        @reloaded_project ||= project.reset
      end
    end
  end
end
