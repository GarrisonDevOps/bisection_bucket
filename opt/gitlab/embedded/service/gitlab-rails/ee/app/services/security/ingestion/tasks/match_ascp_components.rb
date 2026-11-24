# frozen_string_literal: true

module Security
  module Ingestion
    module Tasks
      class MatchAscpComponents < AbstractTask
        def execute
          return unless project.licensed_feature_available?(:security_dashboard)
          return unless Feature.enabled?(:ascp_component_vulnerability_association, project)
          return unless Security::Ascp::Scan.by_project(project.id).exists?

          finding_ids = matchable_finding_maps.map(&:finding_id)
          return if finding_ids.empty?

          SecApplicationRecord.current_transaction.after_commit do
            Gitlab::ApplicationContext.with_context(project: project) do
              Vulnerabilities::UpdateAscpAssociationsBatchWorker.perform_async(project.id, finding_ids)
            end
          end
        end

        private

        def project
          pipeline.project
        end

        def new_finding_maps
          finding_maps.select { |map| map.new_record && (map.tracked_context.nil? || map.tracked_context.is_default?) }
        end

        # ASCP components are keyed by sub_directory, so a finding with no file
        # location can never match one and is expected to stay unmatched. Skip
        # enqueueing those rather than scheduling a worker that would no-op.
        def matchable_finding_maps
          new_finding_maps.select { |map| map.report_finding.location_data.to_h['file'].present? }
        end
      end
    end
  end
end
