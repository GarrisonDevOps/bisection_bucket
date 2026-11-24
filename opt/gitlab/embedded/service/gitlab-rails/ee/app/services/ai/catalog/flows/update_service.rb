# frozen_string_literal: true

module Ai
  module Catalog
    module Flows
      class UpdateService < Items::BaseUpdateService
        extend Gitlab::Utils::Override
        include Concerns::YamlDefinitionParser
        include Concerns::DwsFlowConfigValidator
        include Concerns::AgentReferences

        private

        override :validate_item
        def validate_item
          return error('Flow not found') unless item && item.flow?
          return error(s_('AICatalog|Visibility cannot be blank')) if blank_visibility_given?
          return yaml_definition_error if yaml_definition_error

          references_error = agent_references_error if should_update_definition? || visibility_increasing?
          return references_error if references_error
          return unless should_update_definition?

          dws_result = validate_flow_config_with_dws(definition_parsed)
          error(dws_result.message) if dws_result.error?
        end

        def flow_visibility
          params[:visibility].presence || item.visibility
        end

        def blank_visibility_given?
          params.key?(:visibility) && params[:visibility].blank?
        end

        def visibility_increasing?
          return false unless params[:visibility].present?

          Ai::Catalog::Item.visibility_rank(params[:visibility]) >
            Ai::Catalog::Item.visibility_rank(item.visibility)
        end

        def references_definition
          should_update_definition? ? definition_parsed : item.latest_version.definition
        end

        override :build_version_params
        def build_version_params(_latest_version)
          parsed_definition_param
        end

        override :save_item
        def save_item
          set_dws_validated_on_version(item.latest_version) if should_update_definition?

          save_with_agent_references(item, persist_dependencies: should_update_definition?) { item.save }
        end

        override :latest_schema_version
        def latest_schema_version
          Ai::Catalog::ItemVersion::FLOW_SCHEMA_VERSION
        end

        override :track_update_audit_event
        def track_update_audit_event
          send_audit_events('update_ai_catalog_flow', item, { old_definition: old_definition })
        end
      end
    end
  end
end
