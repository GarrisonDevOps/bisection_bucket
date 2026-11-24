# frozen_string_literal: true

module Security
  module Ingestion
    module Tasks
      class IngestVulnerabilities < AbstractTask
        def execute
          create_new_vulnerabilities
          update_existing_vulnerabilities
          apply_severity_overrides
          mark_redetected_vulnerabilities_as_not_removed_from_code
          mark_resolved_vulnerabilities_as_detected
          create_detection_transitions_for_redetected_vulnerabilities

          finding_maps
        end

        private

        def create_new_vulnerabilities
          IngestVulnerabilities::Create.new(pipeline, new_vulnerability_maps).execute
        end

        def update_existing_vulnerabilities
          IngestVulnerabilities::Update.new(pipeline, existing_vulnerability_maps).execute
          IngestVulnerabilities::SetPresentOnDefaultBranch.new(pipeline, existing_vulnerability_maps).execute
        end

        def apply_severity_overrides
          IngestVulnerabilities::ApplySeverityOverrides.new(pipeline, existing_vulnerability_maps).execute
        end

        def mark_redetected_vulnerabilities_as_not_removed_from_code
          ::Vulnerabilities::RepresentationInformation
            .by_vulnerability(existing_vulnerability_maps.map(&:vulnerability_id))
            .update_all(removed_from_code: false)
        end

        def mark_resolved_vulnerabilities_as_detected
          IngestVulnerabilities::MarkResolvedAsDetected.execute(pipeline, existing_vulnerability_maps)
        end

        def create_detection_transitions_for_redetected_vulnerabilities
          findings = redetected_findings_with_stale_transition
          return if findings.empty?

          ::Vulnerabilities::DetectionTransitions::InsertService.new(findings, detected: true).execute
        end

        def redetected_findings_with_stale_transition
          ::Vulnerabilities::Finding.by_vulnerability_with_stale_detection_transition(vulnerability_ids_not_resolved)
        end

        def vulnerability_ids_not_resolved
          ::Vulnerability
            .with_states(%i[detected confirmed dismissed])
            .id_in(existing_vulnerability_maps.map(&:vulnerability_id))
            .pluck_primary_key
        end

        def partitioned_maps
          @partitioned_maps ||= finding_maps.partition { |finding_map| finding_map.vulnerability_id.nil? }
        end

        def new_vulnerability_maps
          partitioned_maps.first
        end

        # Important Note:
        #   Sorting by vulnerability_id (the locked vulnerabilities.id) is important
        #   to prevent deadlock errors which can happen when concurrent ingestion
        #   transactions (e.g. pipeline and CVS) acquire row locks on the same
        #   vulnerabilities in different order. Both Update and SetPresentOnDefaultBranch
        #   build their bulk UPDATE from these maps, so ordering here covers both.
        def existing_vulnerability_maps
          @existing_vulnerability_maps ||= partitioned_maps.second.sort_by(&:vulnerability_id)
        end
      end
    end
  end
end
