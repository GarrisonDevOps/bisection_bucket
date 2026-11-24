# frozen_string_literal: true

module EE
  module Mcp
    module Tools
      module WorkItems
        module WorkItemsQueryBuilder
          extend ActiveSupport::Concern

          class_methods do
            extend ::Gitlab::Utils::Override

            override :filter_definitions
            def filter_definitions
              super + [
                {
                  key: 'healthStatusFilter',
                  type: 'HealthStatusFilter',
                  transform: ->(v) { v.to_s.camelize(:lower) }
                },
                { key: 'iterationId',         type: '[ID]' },
                { key: 'iterationWildcardId', type: 'IterationWildcardId' },
                { key: 'iterationCadenceId',  type: '[IterationsCadenceID!]' },
                { key: 'weight',              type: 'String' },
                { key: 'weightWildcardId',    type: 'WeightWildcardId' },
                { key: 'status',              type: 'WorkItemWidgetStatusFilterInput' },
                { key: 'customField',         type: '[WorkItemWidgetCustomFieldFilterInputType!]' }
              ]
            end

            override :widget_fragments
            def widget_fragments
              super + [
                <<~GRAPHQL.indent(12),
                  ... on WorkItemWidgetHealthStatus {
                    healthStatus
                  }
                GRAPHQL
                <<~GRAPHQL.indent(12),
                  ... on WorkItemWidgetIteration {
                    iteration {
                      id
                      title
                      startDate
                      dueDate
                      iterationCadence {
                        id
                        title
                      }
                    }
                  }
                GRAPHQL
                <<~GRAPHQL.indent(12),
                  ... on WorkItemWidgetWeight {
                    weight
                  }
                GRAPHQL
                <<~GRAPHQL.indent(12),
                  ... on WorkItemWidgetStatus {
                    status {
                      id
                      name
                    }
                  }
                GRAPHQL
                <<~GRAPHQL.indent(12)
                  ... on WorkItemWidgetCustomFields {
                    customFieldValues {
                      customField {
                        id
                        name
                        fieldType
                      }
                      ... on WorkItemNumberFieldValue {
                        value
                      }
                      ... on WorkItemTextFieldValue {
                        value
                      }
                      ... on WorkItemSelectFieldValue {
                        selectedOptions {
                          id
                          value
                        }
                      }
                    }
                  }
                GRAPHQL
              ]
            end
          end
        end
      end
    end
  end
end
