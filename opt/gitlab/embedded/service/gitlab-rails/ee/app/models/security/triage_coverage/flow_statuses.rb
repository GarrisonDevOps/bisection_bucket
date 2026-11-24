# frozen_string_literal: true

module Security
  module TriageCoverage
    module FlowStatuses
      FLOW_BY_TRIGGER = {
        sbom_ingested: -> { Ai::Catalog::FoundationalFlow.resolve_dependency_bump_experimental },
        sast_false_positive: -> { Ai::Catalog::FoundationalFlow.sast_fp_detection_v1 },
        sast_vulnerability_resolution: -> { Ai::Catalog::FoundationalFlow.resolve_sast_vulnerability_v1 },
        secret_detection_false_positive: -> { Ai::Catalog::FoundationalFlow.secrets_fp_detection_v1 },
        vulnerability_enrichment: nil
      }.freeze

      UNRESOLVED = FLOW_BY_TRIGGER.transform_values { |f| f ? :flow_unavailable : :not_applicable }.freeze

      # Returns { root_group_id => { trigger_type => flow_status } }.
      def self.for_root_ids(root_ids)
        roots = Group.id_in(root_ids).includes(:namespace_settings)
        ::Gitlab::GroupPlansPreloader.new.preload(roots)
        enabled = enabled_references(root_ids)

        roots.to_h { |root| [root.id, statuses_for(root, enabled.fetch(root.id, []))] }
      end

      def self.enabled_references(root_ids)
        Ai::Catalog::EnabledFoundationalFlow.for_namespace(root_ids).includes(:catalog_item)
          .group_by(&:namespace_id)
          .transform_values { |records| records.filter_map { |r| r.catalog_item.foundational_flow_reference } }
      end

      def self.statuses_for(root, enabled)
        flows_enabled = root.duo_foundational_flows_enabled
        stage_available = flows_enabled && Gitlab::Llm::StageCheck.available?(root, :duo_workflow)

        FLOW_BY_TRIGGER.transform_values do |lookup|
          next :not_applicable unless lookup
          next :foundational_flows_disabled unless flows_enabled

          flow = lookup.call
          next :flow_unavailable unless stage_available && flow&.available_for?(root)

          enabled.include?(flow.foundational_flow_reference) ? :available : :flow_not_enabled
        end
      end

      private_class_method :enabled_references, :statuses_for
    end
  end
end
