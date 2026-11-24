# frozen_string_literal: true

module Types
  module Vulnerabilities
    class FindingTokenStatusType < BaseObject
      graphql_name 'VulnerabilityFindingTokenStatus'
      description 'Represents the status of a secret token found in a vulnerability'

      authorize :read_vulnerability

      field :id, GraphQL::Types::ID, null: false,
        description: 'ID of the finding token status.'

      field :status, Types::Vulnerabilities::FindingTokenStatusStateEnum, null: false,
        description: 'Status of the token (unknown, active, inactive).'

      field :created_at, Types::TimeType, null: false,
        description: 'When the token status was created.'

      field :updated_at, Types::TimeType, null: false,
        description: 'When the token status was last updated.'

      field :last_verified_at, Types::TimeType, null: true,
        description: 'When the token was last verified with the issuing service.'
    end
  end
end
