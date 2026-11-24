# frozen_string_literal: true

module Sbom
  module Ingestion
    module Tasks
      class UpdateSecurityPolicyDismissals < Base
        def execute
          policy_dismissals = project.policy_dismissals.for_merge_requests(
            project.merge_requests.by_merged_or_merge_or_squash_commit_sha(@pipeline.sha).select(:id)
          )

          return unless policy_dismissals.present?

          uuids_by_dismissal = Hash.new { |h, k| h[k] = Set.new }

          @occurrence_maps.each do |occurrence_map|
            component_licenses = licenses_fetcher.fetch(occurrence_map.report_component)
            component_name = occurrence_map.name

            component_licenses.each do |license|
              license_name = license&.fetch(:name, nil)
              next unless license_name && component_name

              policy_dismissals.each do |policy_dismissal|
                next unless policy_dismissal.license_names.include?(license_name) &&
                  policy_dismissal.components(license_name).include?(component_name)

                uuids_by_dismissal[policy_dismissal.id] << occurrence_map.uuid
                mark_policy_dismissal_changed(occurrence_map, policy_dismissal)
              end
            end
          end

          uuids_by_dismissal.each do |dismissal_id, uuids|
            sql = Security::PolicyDismissal.sanitize_sql_array([
              "license_occurrence_uuids = ARRAY(
                SELECT DISTINCT unnest(license_occurrence_uuids || ARRAY[?]::text[]))",
              uuids.to_a
            ])

            Security::PolicyDismissal.id_in(dismissal_id).update_all(sql)
          end
        end

        private

        def mark_policy_dismissal_changed(occurrence_map, policy_dismissal)
          # Only a preserved dismissal changes the indexed policy_violations value. An open one is
          # re-indexed when it is preserved, by Sbom::TrackPolicyDismissalOccurrenceRefsWorker.
          return unless policy_dismissal.preserved?
          return if policy_dismissal.license_occurrence_uuids.include?(occurrence_map.uuid)

          occurrence_map.policy_dismissal_changed = true
        end

        def licenses_fetcher
          Sbom::Ingestion::LicensesFetcher.new(project, occurrence_maps)
        end
        strong_memoize_attr :licenses_fetcher
      end
    end
  end
end
