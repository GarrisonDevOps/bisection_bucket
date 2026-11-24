# frozen_string_literal: true

module Sbom
  class CreateVulnerabilitiesService
    include Gitlab::Utils::StrongMemoize
    include Gitlab::VulnerabilityScanning::AdvisoryUtils
    include Gitlab::InternalEventsTracking

    def self.execute(pipeline_id)
      new(pipeline_id).execute
    end

    def initialize(pipeline_id)
      @pipeline_id = pipeline_id
      @possibly_affected_sbom_occurrences_count = 0
      @known_affected_sbom_occurrences_count = 0
      @sbom_occurrences_semver_dialects_errors_count = 0
      @vulnerability_scanning_errors = []
    end

    def execute
      start_time = Time.current.iso8601

      ingested_ids_by_report_type = scan_sbom_reports

      mark_resolved_vulnerabilities(ingested_ids_by_report_type)

      persist_vulnerability_scanning_errors

      track_internal_event(
        'cvs_on_sbom_change',
        project: project,
        additional_properties: {
          label: 'pipeline_info',
          property: pipeline_id.to_s,
          start_time: start_time,
          end_time: Time.current.iso8601,
          possibly_affected_sbom_occurrences: possibly_affected_sbom_occurrences_count,
          known_affected_sbom_occurrences: known_affected_sbom_occurrences_count,
          sbom_occurrences_semver_dialects_errors_count: sbom_occurrences_semver_dialects_errors_count
        }
      )
    end

    attr_reader :pipeline_id, :possibly_affected_sbom_occurrences_count, :known_affected_sbom_occurrences_count,
      :sbom_occurrences_semver_dialects_errors_count

    private

    def scan_sbom_reports
      ingested_ids_by_report_type = Hash.new([])

      valid_sbom_reports.each do |sbom_report|
        unless sbom_report.source.present?
          track_missing_source_error unless sbom_report.third_party?
          next
        end

        source_type = sbom_report.source.source_type

        # Skip dependency_scanning SBOM reports (DS findings are now ingested during the main ingestion process)
        # Skip other source types when the cvs_for_container_scanning feature flag is disabled
        next if source_type == :dependency_scanning || Feature.disabled?(:cvs_for_container_scanning, project)

        sbom_report.components.each_slice(::Security::IngestionConstants::COMPONENTS_BATCH_SIZE) do |occurrence_batch|
          @possibly_affected_sbom_occurrences_count += occurrence_batch.count

          affected_packages(occurrence_batch).each_batch do |affected_package_batch|
            finding_maps = affected_package_batch.filter_map do |affected_package|
              # We need to match every affected package to one occurrence
              affected_occurrence = occurrence_batch.find do |occurrence|
                next unless affected_package.package_name == occurrence.name

                affected_occurrence?(occurrence, sbom_report.source, affected_package)
              end

              next unless affected_occurrence.present?

              @known_affected_sbom_occurrences_count += 1

              advisory_data_object = Gitlab::VulnerabilityScanning::Advisory.from_affected_package(
                affected_package: affected_package, advisory: affected_package.advisory)

              Security::VulnerabilityScanning::BuildFindingMapService.execute(
                advisory: advisory_data_object,
                affected_component: affected_occurrence,
                source: sbom_report.source,
                pipeline: pipeline,
                project: project,
                purl_type: affected_occurrence.purl.type,
                scanner: scanner,
                tracked_context: tracked_context
              )
            end

            ingested_ids_by_report_type[sbom_report.source.source_type] +=
              create_vulnerabilities(finding_maps, scan_type: :advisory)
          end
        end
      end

      ingested_ids_by_report_type
    end

    def affected_occurrence?(occurrence, source, affected_package)
      advisory = affected_package.advisory

      occurrence_is_affected?(
        xid: advisory.advisory_xid,
        purl_type: affected_package.purl_type,
        range: affected_package.affected_range,
        version: occurrence.version,
        distro: affected_package.distro_version,
        source: source,
        project_id: pipeline.project_id,
        source_xid: advisory.source_xid
      )
    rescue SemverDialects::Error
      @sbom_occurrences_semver_dialects_errors_count += 1
      false
    end

    def affected_packages(occurrence_batch)
      ::PackageMetadata::AffectedPackage.for_occurrences(occurrence_batch).with_advisory
    end

    def all_sbom_reports
      pipeline.sbom_reports(self_and_project_descendants: true).reports
    end

    def valid_sbom_reports
      all_sbom_reports.select(&:valid?)
    end
    strong_memoize_attr :valid_sbom_reports

    def pipeline
      Ci::Pipeline.find(pipeline_id)
    end
    strong_memoize_attr :pipeline

    def project
      pipeline.project
    end
    strong_memoize_attr :project

    def scanner
      ::Gitlab::VulnerabilityScanning::SecurityScanner.fabricate
    end
    strong_memoize_attr :scanner

    def tracked_context
      result = ::Security::ProjectTrackedContexts::FindOrCreateService.from_pipeline(pipeline).execute!

      raise ArgumentError, result.message unless result.success?

      result.payload[:tracked_context]
    end
    strong_memoize_attr :tracked_context

    def mark_resolved_vulnerabilities(ingested_ids_by_report_type)
      # MarkAsResolvedService expects a persisted scanner record.
      scanner = Vulnerabilities::Scanner.sbom_scanner(project_id: project.id)

      ingested_ids_by_report_type.each do |report_type, ingested_ids|
        # TODO: The ingested ids can be duplicated when returned from create_vulnerabilities, so we
        # remove duplicates here to avoid iterating through the same ids.
        # See https://gitlab.com/gitlab-org/gitlab/-/issues/519156 for more details.
        ::Security::Ingestion::MarkAsResolvedService.execute(pipeline, scanner, ingested_ids.uniq, tracked_context,
          report_type)
      end
    end

    def track_missing_source_error
      error_msg = "Required GitLab CycloneDX properties are missing. " \
        "This will prevent vulnerability scanning and may result in incomplete license and package information."
      help_link = "user/application_security/dependency_scanning/dependency_scanning_sbom/#bringing-your-own-sbom"

      @vulnerability_scanning_errors << { message: error_msg, help_link: help_link }
    end

    def persist_vulnerability_scanning_errors
      return if @vulnerability_scanning_errors.empty?

      pipeline.set_sbom_report_ingestion_errors(@vulnerability_scanning_errors)
    end
  end
end
