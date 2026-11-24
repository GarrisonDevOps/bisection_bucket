# frozen_string_literal: true

module Types
  module Vulnerabilities
    # rubocop: disable Graphql/AuthorizeTypes -- Authorization is at vulnerability level
    class SeverityOverrideType < BaseObject
      graphql_name 'SeverityOverride'
      description "Represents a vulnerability severity override"

      field :original_severity, ::Types::VulnerabilitySeverityEnum,
        null: false, description: 'Original severity of the vulnerability.'

      field :new_severity, ::Types::VulnerabilitySeverityEnum,
        null: false, description: 'New severity of the vulnerability.'

      field :author, ::Types::UserType,
        null: false, description: 'User who changed the severity.'

      field :created_at, TimeType,
        null: true, description: 'Time of severity change.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
