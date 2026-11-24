# frozen_string_literal: true

module Types
  module Security
    # rubocop:disable Graphql/AuthorizeTypes -- Authorization is done on the Project field
    class TriageAndRemediationCoverageType < BaseObject
      graphql_name 'TriageAndRemediationCoverage'
      description 'Triage and remediation capability coverage for a project.'

      authorize_granular_token permissions: :read_security_scan_profiles,
        boundary: :project, boundary_type: :project

      Adapter = Struct.new(:capabilities, :project, keyword_init: true)

      field :capabilities, [Types::Security::TriageAndRemediationCapabilityType],
        null: false,
        experiment: { milestone: '19.5' },
        description: 'Triage and remediation capabilities and their coverage state, one entry per trigger type.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
