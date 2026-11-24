# frozen_string_literal: true

module EE
  module Mcp
    module Tools
      module WorkItems
        module SaveWorkItemService
          extend ::Gitlab::Utils::Override

          override :input_schema
          def input_schema
            super.deep_merge(
              properties: {
                health_status: {
                  type: 'string',
                  enum: ::Types::HealthStatusEnum.values.keys,
                  description: 'Health status of the work item.'
                },
                weight: {
                  type: 'integer',
                  minimum: 0,
                  description: 'Weight of the work item.'
                },
                clear_weight: {
                  type: 'boolean',
                  description: 'Update only. Removes the weight; wins over weight.'
                },
                status_id: {
                  type: 'string',
                  description: 'Global ID of the status to set.'
                },
                is_fixed: {
                  type: 'boolean',
                  description: 'Whether start and due dates are fixed. When false, dates roll up ' \
                    'from child items and start_date/due_date are ignored.'
                },
                agent_plan: {
                  type: 'string',
                  description: 'Markdown content of the agent plan. Requires the workplan feature.'
                },
                readiness_score: {
                  type: 'integer',
                  minimum: 0,
                  maximum: 100,
                  description: 'Readiness score of the agent plan (0-100). ' \
                    'Requires the workplan feature. ' \
                    'Omit to leave the existing score unchanged.'
                }
              }
            )
          end
        end
      end
    end
  end
end
