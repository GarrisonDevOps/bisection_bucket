# frozen_string_literal: true

module Ai
  module Catalog
    module ThirdPartyFlows
      class AuditEventMessageService < Items::BaseAuditEventMessageService
        private

        def item_type
          'third_party_flow'
        end

        def expected_schema_version
          # THIRD_PARTY_FLOW_SCHEMA_VERSION
          # Update this when Ai::Catalog::ItemVersion::THIRD_PARTY_FLOW_SCHEMA_VERSION changes
          1
        end

        def create_messages
          messages = []

          messages << "Created a new #{visibility_label} AI external agent"

          messages << version_message(item.latest_version)

          messages
        end

        def build_change_descriptions
          descriptions = []

          old_def, new_def = get_definition_comparison
          return descriptions unless old_def && new_def

          descriptions << 'Changed image' if old_def['image'] != new_def['image']
          descriptions << 'Changed commands' if old_def['commands'] != new_def['commands']
          descriptions << 'Changed variables' if old_def['variables'] != new_def['variables']

          if inject_gateway_token_changed?(old_def, new_def)
            descriptions << inject_gateway_token_change_message(new_def)
          end

          descriptions
        end

        def inject_gateway_token_changed?(old_def, new_def)
          old_def['injectGatewayToken'] != new_def['injectGatewayToken']
        end

        def inject_gateway_token_change_message(new_def)
          if new_def['injectGatewayToken']
            'Enabled AI Gateway token injection'
          else
            'Disabled AI Gateway token injection'
          end
        end
      end
    end
  end
end
