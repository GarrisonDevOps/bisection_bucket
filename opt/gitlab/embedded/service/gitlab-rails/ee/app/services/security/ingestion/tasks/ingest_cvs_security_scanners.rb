# frozen_string_literal: true

module Security
  module Ingestion
    module Tasks
      class IngestCvsSecurityScanners < AbstractTask
        include Gitlab::Ingestion::BulkInsertableTask

        self.model = Vulnerabilities::Scanner
        self.unique_by = %i[project_id external_id].freeze
        self.uses = %i[project_id id]

        private

        def attributes
          finding_maps.filter_map do |finding_map|
            next if existing_scanners_by_project_id.include?(finding_map.project.id)

            {
              project_id: finding_map.project.id,
              external_id: Gitlab::VulnerabilityScanning::SecurityScanner::EXTERNAL_ID,
              name: Gitlab::VulnerabilityScanning::SecurityScanner::NAME,
              vendor: Gitlab::VulnerabilityScanning::SecurityScanner::VENDOR
            }.freeze
          end
        end

        def after_ingest
          finding_maps.each do |finding_map|
            finding_map.scanner_id = get_scanner_id(finding_map)
          end
        end

        def get_scanner_id(finding_map)
          scanners_by_project_id[finding_map.project.id]
        end

        def scanners_by_project_id
          @scanners_by_project_id ||= existing_scanners_by_project_id.merge!(return_data.to_h)
        end

        def existing_scanners_by_project_id
          # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- The pluck call here reduces the data returned, and allows for
          # the transormation into a hash where the project_id are the keys and the scanner_id are the values. The
          # `limit` call is also omitted since we have a set batch finding map size. Additionally, there's a unique
          # index on the project_id and id, so we're not expected to see more results than the given batch size.
          @existing_scanners_by_project_id ||= Vulnerabilities::Scanner
            .for_projects(project_ids)
            .with_external_id(Gitlab::VulnerabilityScanning::SecurityScanner::EXTERNAL_ID)
            .pluck(:project_id, :id)
            .to_h
          # rubocop:enable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit
        end

        def project_ids
          finding_maps.map { |finding_map| finding_map.project.id }.uniq
        end
      end
    end
  end
end
