# frozen_string_literal: true

module EE
  module Mcp
    module Tools
      module WorkItems
        module ListWorkItemsService
          extend ::Gitlab::Utils::Override

          # The three real statuses only: the NONE/ANY wildcards are mangled
          # by the shared camelize(:lower) filter transform, so they are
          # deliberately cut from v1 (adding them later is additive).
          HEALTH_STATUS_VALUES = %w[onTrack needsAttention atRisk].freeze

          override :input_schema
          def input_schema
            super.deep_merge(
              properties: {
                health_status_filter: {
                  type: 'string',
                  enum: HEALTH_STATUS_VALUES,
                  description: 'Filter by health status.'
                },
                status: {
                  type: 'object',
                  properties: {
                    name: {
                      type: 'string',
                      description: 'Status name, for example "In progress".'
                    }
                  },
                  required: %w[name],
                  additionalProperties: false,
                  description: 'Filter by custom status.'
                }
              }
            )
          end
        end
      end
    end
  end
end
