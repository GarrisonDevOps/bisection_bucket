# frozen_string_literal: true

module Types
  module Vulnerabilities
    class FlagType < BaseObject
      graphql_name 'VulnerabilityFlag'
      description 'Represents a flag result for a vulnerability'

      authorize :read_vulnerability

      def self.authorization_scopes
        super + [:ai_workflows]
      end

      field :id, GraphQL::Types::ID, null: false,
        description: 'ID of the false positive detection.',
        scopes: [:api, :read_api, :ai_workflows]

      field :status, Types::Vulnerabilities::Flags::FalsePositiveDetectionStatusEnum, null: true,
        experiment: { milestone: '18.5' },
        description: 'Status of the false positive detection.',
        scopes: [:api, :read_api, :ai_workflows]

      field :confidence_score, GraphQL::Types::Float, null: true,
        experiment: { milestone: '18.5' },
        description: 'Confidence score of the detection (0.0 to 1.0).',
        scopes: [:api, :read_api, :ai_workflows]

      field :origin, GraphQL::Types::String, null: true,
        description: 'Origin of service that raising the flag on the vulnerability.',
        scopes: [:api, :read_api, :ai_workflows]

      field :description, GraphQL::Types::String, null: true,
        description: 'Reasoning for the raising of the flag on the vulnerability.',
        scopes: [:api, :read_api, :ai_workflows]

      field :created_at, Types::TimeType, null: false,
        description: 'Timestamp when the detection was created.',
        scopes: [:api, :read_api, :ai_workflows]

      field :updated_at, Types::TimeType, null: false,
        description: 'Timestamp when the detection was last updated.',
        scopes: [:api, :read_api, :ai_workflows]
    end
  end
end
