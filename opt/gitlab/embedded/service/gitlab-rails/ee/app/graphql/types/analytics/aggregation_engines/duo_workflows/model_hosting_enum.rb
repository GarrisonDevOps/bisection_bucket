# frozen_string_literal: true

module Types
  module Analytics
    module AggregationEngines
      module DuoWorkflows
        class ModelHostingEnum < ::Types::BaseEnum
          graphql_name 'DuoWorkflowsModelHosting'
          description 'Where a model used by GitLab Duo Agent Platform flows is hosted.'

          value 'GITLAB', value: :gitlab,
            description: 'Model served through GitLab-managed infrastructure.'
          value 'SELF_HOSTED', value: :self_hosted,
            description: 'Model configured as a self-hosted model on the instance.'
        end
      end
    end
  end
end
