# frozen_string_literal: true

module EE
  module Mcp
    module Tools
      module WorkItems
        module LinkWorkItemsService
          extend ::Gitlab::Utils::Override

          EE_LINK_TYPE_ENUM = %w[relates_to blocks blocked_by].freeze

          override :description
          def description
            'Link a work item to other work items with a relationship type (relates_to, blocks, blocked_by)'
          end

          override :input_schema
          def input_schema
            super.deep_merge(
              properties: {
                link_type: {
                  enum: EE_LINK_TYPE_ENUM
                }
              }
            )
          end
        end
      end
    end
  end
end
