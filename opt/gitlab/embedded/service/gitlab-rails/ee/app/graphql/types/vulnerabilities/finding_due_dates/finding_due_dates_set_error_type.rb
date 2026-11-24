# frozen_string_literal: true

module Types
  module Vulnerabilities
    module FindingDueDates
      # rubocop: disable Graphql/AuthorizeTypes -- part of aggregated payload, authorization handled upstream
      class FindingDueDatesSetErrorType < BaseObject
        graphql_name 'FindingDueDatesSetError'
        description 'Represents an error encountered while setting due dates for a vulnerability finding.'

        authorize_granular_token parent_authorizes: :update_finding_due_date

        field :finding_uuid,
          String,
          null: true,
          method: :uuid,
          description: 'UUID of the vulnerability finding associated with the error.'

        field :code,
          String,
          null: false,
          description: 'Machine-readable error code.'

        field :message,
          String,
          null: false,
          description: 'Human-readable error message.'
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
