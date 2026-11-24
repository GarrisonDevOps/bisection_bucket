# frozen_string_literal: true

module Types
  module Security
    # rubocop: disable Graphql/AuthorizeTypes -- Authorization is done in resolver layer
    class VulnerabilitiesPerSeverityType < BaseObject
      graphql_name 'VulnerabilitiesPerSeverity'
      description 'Represents vulnerability counts grouped by severity level'

      # Only SecurityMetrics.vulnerabilitiesPerSeverity returns it.
      authorize_granular_token skip_reason: :parent_authorizes

      ::Enums::Vulnerability.severity_levels.each_key do |severity|
        field severity.to_s,
          Types::Security::VulnerabilitySeverityCountType,
          null: true,
          description: "Number of #{severity.upcase} severity vulnerabilities."
      end
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
