# frozen_string_literal: true

module EE
  module Gitlab
    module BackgroundMigration
      module BackfillTriageCapabilitiesInSecurityInventoryFilters
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        # From Enums::Security::REMEDIATION_SCAN_PROFILE_TYPES
        DEPENDENCY_SCANNING_POST_PROCESSING = 20
        TRIAGE_AND_REMEDIATION = 30

        # From Enums::Security::SCAN_PROFILE_TRIGGER_TYPES / REMEDIATION_SCAN_PROFILE_TRIGGER_TYPES
        SBOM_INGESTED = 3
        NON_SBOM_TRIGGERS = [10, 11, 12, 13].freeze

        # Bit position mirrors Security::TriageCoverage::CapabilityBitmask::BITS
        TRIGGER_MASKS = {
          SBOM_INGESTED => 1,
          10 => 2, # sast_false_positive
          11 => 4, # sast_vulnerability_resolution
          12 => 8, # secret_detection_false_positive
          13 => 16 # vulnerability_enrichment
        }.freeze

        class SecurityInventoryFilter < ::SecApplicationRecord
          self.table_name = 'security_inventory_filters'
        end

        class SecurityScanProfile < ::SecApplicationRecord
          self.table_name = 'security_scan_profiles'

          has_many :scan_profiles_projects, class_name: 'SecurityScanProfileProject', inverse_of: :scan_profile

          scope :not_deleted, -> { where(deleted_at: nil) }
        end

        class SecurityScanProfileProject < ::SecApplicationRecord
          self.table_name = 'security_scan_profiles_projects'

          belongs_to :scan_profile, class_name: 'SecurityScanProfile',
            foreign_key: :security_scan_profile_id, inverse_of: :scan_profiles_projects
        end

        class SecurityScanProfileConfiguration < ::SecApplicationRecord
          self.table_name = 'security_scan_profile_configurations'
        end

        class SecurityScanProfileTrigger < ::SecApplicationRecord
          self.table_name = 'security_scan_profile_triggers'

          belongs_to :scan_profile, class_name: 'SecurityScanProfile', foreign_key: :security_scan_profile_id
          belongs_to :configuration, class_name: 'SecurityScanProfileConfiguration',
            foreign_key: :security_scan_profile_configuration_id, optional: true
        end

        prepended do
          operation_name :backfill_triage_capabilities_in_security_inventory_filters
          feature_category :security_asset_inventories
        end

        override :perform
        def perform
          each_sub_batch do |sub_batch|
            project_ids = sub_batch.distinct.pluck(:project_id)
            upsert_capabilities(masks_by_project_for(project_ids))
          end
        end

        private

        # Lowest scan-profile id wins per (project, trigger_type) Every project seeded at 0/0 so this is full recompute
        def masks_by_project_for(project_ids)
          rows =
            winning_trigger_rows(project_ids, [SBOM_INGESTED], [DEPENDENCY_SCANNING_POST_PROCESSING,
              TRIAGE_AND_REMEDIATION]) +
            winning_trigger_rows(project_ids, NON_SBOM_TRIGGERS, [TRIAGE_AND_REMEDIATION])

          run_modes = run_modes_for(rows.filter_map { |_, _, configuration_id| configuration_id })

          rows.each_with_object(project_ids.index_with { { on: 0, auto: 0 } }) do |row, result|
            project_id, trigger_type, configuration_id = row
            mask = TRIGGER_MASKS.fetch(trigger_type)
            is_auto = trigger_type == SBOM_INGESTED || run_modes[configuration_id] != 'manual'

            result[project_id][:on] |= mask
            result[project_id][:auto] |= mask if is_auto
          end
        end

        def winning_trigger_rows(project_ids, trigger_types, scan_types)
          SecurityScanProfileTrigger
            .joins(scan_profile: :scan_profiles_projects)
            .merge(SecurityScanProfile.not_deleted.where(scan_type: scan_types))
            .where(trigger_type: trigger_types, security_scan_profiles_projects: { project_id: project_ids })
            .order(:security_scan_profile_id)
            .pluck('security_scan_profiles_projects.project_id', :trigger_type, :security_scan_profile_configuration_id)
            .group_by { |project_id, trigger_type, _| [project_id, trigger_type] }
            .values
            .map(&:first) # rows are sorted by id, so first is lowest
        end

        def run_modes_for(configuration_ids)
          return {} if configuration_ids.empty?

          SecurityScanProfileConfiguration.where(id: configuration_ids).index_by(&:id)
            .transform_values { |configuration| configuration.configuration['run_mode'] }
        end

        def upsert_capabilities(masks_by_project)
          existing_filters = SecurityInventoryFilter
            .select(:project_id, :project_name, :traversal_ids, :archived)
            .where(project_id: masks_by_project.keys)
            .index_by(&:project_id)

          records = masks_by_project.filter_map do |project_id, masks|
            filter = existing_filters[project_id]
            next unless filter

            filter.attributes.slice('project_id', 'project_name', 'traversal_ids', 'archived').merge(
              'triage_capabilities_on' => masks[:on],
              'triage_capabilities_auto' => masks[:auto]
            )
          end

          return if records.empty?

          SecurityInventoryFilter.upsert_all(
            records, unique_by: :project_id,
            update_only: [:triage_capabilities_on, :triage_capabilities_auto]
          )
        end
      end
    end
  end
end
