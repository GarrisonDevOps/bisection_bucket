# frozen_string_literal: true

module Ai
  module Catalog
    module Concerns
      module DwsFlowConfigValidator
        extend ActiveSupport::Concern

        private

        def validate_flow_config_with_dws(definition_hash)
          ::Ai::Catalog::Items::ValidateConfigService
            .new(container: project, current_user: current_user)
            .execute(definition_hash)
        end

        def set_dws_validated_on_version(item_version)
          item_version.dws_flow_config_validated = true
        end
      end
    end
  end
end
