# frozen_string_literal: true

module Ai
  module Catalog
    module Concerns
      module AgentReferences
        extend ActiveSupport::Concern
        include Gitlab::Utils::StrongMemoize

        private

        def agent_references_error
          return unless references_definition.is_a?(Hash) && references_definition.key?('include')

          unless Feature.enabled?(:ai_catalog_flow_agent_references, project)
            return error(s_('AICatalog|Referencing AI Catalog items with include is not available'))
          end

          unless ::Gitlab::Llm::StageCheck.available?(project, :ai_catalog_flow_agent_references)
            return error(
              s_('AICatalog|Referencing AI Catalog items with include needs experiment and beta features turned on')
            )
          end

          return if agent_reference_resolution.success?

          error(agent_reference_resolution.message)
        end

        def agent_reference_resolution
          Flows::ReferenceResolver.new(
            user: current_user,
            flow_project: project,
            definition: references_definition,
            flow_visibility: flow_visibility
          ).execute
        end
        strong_memoize_attr :agent_reference_resolution

        def save_with_agent_references(item, persist_dependencies: true)
          Ai::Catalog::Item.transaction do
            raise ActiveRecord::Rollback unless yield
            next true unless persist_dependencies

            begin
              persist_agent_references(item.latest_version)
            rescue ActiveRecord::InvalidForeignKey, ActiveRecord::RecordNotUnique, ActiveRecord::RecordInvalid
              item.errors.add(:base, s_('AICatalog|Referenced agents changed while the flow was saved. Try again.'))
              raise ActiveRecord::Rollback
            end

            true
          end || false
        end

        def references_definition
          definition_parsed
        end

        def persist_agent_references(item_version)
          rows = agent_reference_resolution.payload[:agents].map do |resolved|
            Ai::Catalog::ItemVersionDependency.new(
              ai_catalog_item_version: item_version,
              dependency: resolved.item,
              dependency_version: resolved.version,
              organization_id: item_version.organization_id
            )
          end

          Ai::Catalog::ItemVersionDependency.transaction do
            Ai::Catalog::ItemVersionDependency.for_item_version(item_version).delete_all
            Ai::Catalog::ItemVersionDependency.bulk_insert!(rows)
          end
        end
      end
    end
  end
end
