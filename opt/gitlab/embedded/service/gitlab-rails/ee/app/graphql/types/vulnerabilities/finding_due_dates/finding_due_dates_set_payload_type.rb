# frozen_string_literal: true

module Types
  module Vulnerabilities
    module FindingDueDates
      # rubocop: disable Graphql/AuthorizeTypes -- part of aggregated payload, authorization handled upstream
      class FindingDueDatesSetPayloadType < BaseObject
        graphql_name 'FindingDueDatesSetPayload'

        authorize_granular_token skip_reason: :parent_authorizes

        field :assigned,
          Integer,
          null: true,
          description: 'Number of findings for which a due date was successfully assigned.'

        field :removed,
          Integer,
          null: true,
          description: 'Number of findings for which a due date was successfully removed.'

        field :skipped,
          Integer,
          null: true,
          description: 'Number of findings that were skipped due to errors or not found.'

        field :errors,
          [Types::Vulnerabilities::FindingDueDates::FindingDueDatesSetErrorType],
          null: false,
          description: "Errors encountered during the mutation. " \
            "A maximum of #{Mutations::Vulnerabilities::BulkSetVulnerabilityFindingsDueDates::MAX_ERRORS} " \
            "errors are returned per request."
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
