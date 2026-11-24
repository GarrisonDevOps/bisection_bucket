# frozen_string_literal: true

module Security
  module Ingestion
    module Tasks
      class IngestVulnerabilities
        # Sets `present_on_default_branch` attributes of vulnerabilities
        # as `true` for those with `false` values and marks the related
        # `finding_map` objects as `new_record`.
        class SetPresentOnDefaultBranch < AbstractTask
          include Gitlab::Ingestion::BulkUpdatableTask

          self.model = Vulnerability
          self.scope = 'vulnerabilities.present_on_default_branch IS FALSE'

          private

          def after_update(updated_vulnerability_ids)
            updated_vulnerability_ids.each do |updated_vulnerability_id|
              set_finding_map_as_new_record_for(updated_vulnerability_id)
            end
          end

          def set_finding_map_as_new_record_for(vulnerability_id)
            updated_finding_map = finding_maps.find { |fm| fm.vulnerability_id == vulnerability_id }

            updated_finding_map.new_record = true
          end

          def attributes
            finding_maps.map do |finding_map|
              attributes_for(
                finding_map.vulnerability_id,
                finding_map.report_finding,
                finding_map.finding_id
              )
            end
          end

          def attributes_for(vulnerability_id, report_finding, finding_id)
            {
              id: vulnerability_id,
              title: report_finding.name.truncate(::Issuable::TITLE_LENGTH_MAX),
              severity: report_finding.severity,
              resolved_on_default_branch: false,
              updated_at: Time.zone.now,
              present_on_default_branch: true,
              cvss: report_finding.cvss,
              finding_id: finding_id
            }
          end
        end
      end
    end
  end
end
