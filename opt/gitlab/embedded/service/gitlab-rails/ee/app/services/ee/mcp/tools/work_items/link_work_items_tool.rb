# frozen_string_literal: true

module EE
  module Mcp
    module Tools
      module WorkItems
        module LinkWorkItemsTool
          extend ::Gitlab::Utils::Override

          EE_LINK_TYPE_MAPPING = {
            'blocks' => 'BLOCKS',
            'blocked_by' => 'BLOCKED_BY'
          }.freeze

          override :normalized_link_type
          def normalized_link_type
            link_type = params[:link_type].to_s.downcase

            # CE types (blank, relates_to) - let CE handle it
            return super unless EE_LINK_TYPE_MAPPING.key?(link_type)

            # EE-only types need license check
            unless blocked_work_items_available?
              raise ArgumentError, 'Blocked work items are not available for the current subscription tier'
            end

            EE_LINK_TYPE_MAPPING[link_type]
          end

          private

          def blocked_work_items_available?
            resolve_parent[:record].licensed_feature_available?(:blocked_work_items)
          end
        end
      end
    end
  end
end
