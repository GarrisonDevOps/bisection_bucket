# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      # rubocop:disable Graphql/AuthorizeTypes -- Disabling widget level authorization
      class VulnerabilitiesType < BaseObject
        graphql_name 'WorkItemWidgetVulnerabilities'
        description 'Represents a vulnerabilities widget'

        authorize_granular_token skip_reason: :parent_authorizes

        implements ::Types::WorkItems::WidgetInterface

        field :related_vulnerabilities, ::Types::Vulnerabilities::CountableVulnerabilityType.connection_type,
          null: true,
          description: 'Related vulnerabilities of the work item.',
          experiment: { milestone: '17.10' }
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
