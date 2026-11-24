# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Pipeline
        module Chain
          module CreateCrossDatabaseAssociations
            extend ::Gitlab::Utils::Override
            include ::Gitlab::Ci::Pipeline::Chain::Helpers

            override :perform!
            def perform!
              create_dast_associations
              persist_scan_profile_mappings
            end

            override :break?
            def break?
              pipeline.errors.any?
            end

            private

            def create_dast_associations
              # we don't use pipeline.stages.by_name because it introduces an extra sql query
              dast_stage = pipeline.stages.find { |stage| stage.name == ::AppSec::Dast::ScanConfigs::BuildService::STAGE_NAME }
              return unless dast_stage

              response = AppSec::Dast::Profiles::CreateAssociationsService.new(
                project: project,
                current_user: current_user,
                params: {
                  builds: dast_stage.statuses, # we use dast_stage.statuses to avoid extra sql queries
                  project: command.project
                }
              ).execute

              error(response.errors.join(', '), failure_reason: :config_error) if response.error?
            rescue ActiveRecord::ActiveRecordError => e
              ::Gitlab::ErrorTracking.track_and_raise_for_dev_exception(e, extra: { pipeline_id: pipeline.id })

              error('Failed to associate DAST profiles')
            end

            def persist_scan_profile_mappings
              ::Gitlab::Ci::Pipeline::SecurityScanProfiles::ScanProfileMappingStore.persist_mappings(
                pipeline: pipeline,
                context: command.scan_profile_context
              )
            end
          end
        end
      end
    end
  end
end
