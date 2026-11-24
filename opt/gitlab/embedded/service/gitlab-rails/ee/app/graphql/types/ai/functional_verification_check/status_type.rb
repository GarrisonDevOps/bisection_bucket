# frozen_string_literal: true

module Types
  module Ai
    module FunctionalVerificationCheck
      # rubocop:disable Graphql/AuthorizeTypes -- see the authorize_granular_token call below
      class StatusType < Types::BaseObject
        graphql_name 'FunctionalVerificationStatus'
        description 'Status of a GitLab Duo Agent Platform functional verification check.'

        authorize_granular_token permissions: :read_functional_verification_check, boundary: :instance,
          boundary_type: :instance

        field :state, Types::Ai::FunctionalVerificationCheck::StateEnum,
          null: false, description: 'State of the verification run.'

        field :message, GraphQL::Types::String,
          null: true, description: 'Message describing the result of the latest failed run.'

        field :updated_at, Types::TimeType,
          null: true, description: 'Timestamp the latest run was last updated at.',
          hash_key: :checked_at
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
