# frozen_string_literal: true

module Security
  module TriageCoverage
    module ProjectCapabilities
      MISSING_FLOW_STATUSES = %i[foundational_flows_disabled flow_unavailable flow_not_enabled].freeze

      def self.for_projects(projects)
        project_ids = projects.map(&:id)
        filters_by_project_id = Security::InventoryFilter.by_project_id(project_ids).index_by(&:project_id)
        flow_statuses = flow_statuses_by_project_id(projects, project_ids)

        projects.to_h do |project|
          capabilities = filters_by_project_id[project.id]&.triage_capabilities || CapabilityBitmask.decode(0, 0)
          statuses = flow_statuses.fetch(project.id)

          [project.id, capabilities.map { |c| c.merge(flow_status: statuses.fetch(c[:trigger_type])) }]
        end
      end

      def self.missing_flows_masks(root_ids)
        statuses_by_root = FlowStatuses.for_root_ids(root_ids)

        root_ids.index_with do |root_id|
          statuses_by_root.fetch(root_id, FlowStatuses::UNRESOLVED).sum do |trigger_type, status|
            MISSING_FLOW_STATUSES.include?(status) ? CapabilityBitmask.mask_for(trigger_type) : 0
          end
        end
      end

      def self.flow_statuses_by_project_id(projects, project_ids)
        return {} if projects.blank?

        root_id_by_project = Project.root_namespace_ids_by_project_ids(project_ids)
        by_root = FlowStatuses.for_root_ids(root_id_by_project.values.uniq)

        projects.to_h do |project|
          [project.id, by_root.fetch(root_id_by_project[project.id], FlowStatuses::UNRESOLVED)]
        end
      end

      private_class_method :flow_statuses_by_project_id
    end
  end
end
