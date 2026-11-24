# frozen_string_literal: true

module Types
  module SecurityOrchestration
    class PolicyScanFindingViolationType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorized via resolver
      graphql_name 'PolicyScanFindingViolation'
      description 'Represents policy violation for `scan_finding` report_type'

      field :name,
        type: GraphQL::Types::String,
        null: true,
        description: 'Represents the name of the finding.'

      field :report_type,
        type: VulnerabilityReportTypeEnum,
        null: false,
        description: 'Represents the report type.'

      field :severity,
        type: VulnerabilitySeverityEnum,
        null: true,
        description: 'Severity of the finding.'

      field :location,
        type: GraphQL::Types::JSON,
        null: true,
        description: 'Location of the finding determined by the scanner.'

      field :path,
        type: GraphQL::Types::String,
        null: true,
        description: 'Represents the URL path to the finding.'
    end
  end
end
