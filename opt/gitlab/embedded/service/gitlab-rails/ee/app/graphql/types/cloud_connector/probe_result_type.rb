# frozen_string_literal: true

# rubocop: disable Graphql/AuthorizeTypes -- this should be callable by anyone

module Types
  module CloudConnector
    class ProbeResultType < Types::BaseObject
      graphql_name 'CloudConnectorProbeResult'

      authorize_granular_token parent_authorizes: :check_ai_self_hosted_model_connection

      field :name, GraphQL::Types::String, null: true,
        description: 'Name of the probe.'

      field :success, GraphQL::Types::Boolean, null: true,
        description: 'Indicates if the probe was successful.'

      field :message, GraphQL::Types::String, null: true,
        description: 'Additional message or details about the probe result.'

      field :errors, [GraphQL::Types::String], null: true,
        description: 'Full list of errors about the probe result.'

      field :details, GraphQL::Types::JSON, null: true, # rubocop:disable Graphql/JSONType -- Different type of probes will have different details
        description: 'Additional details about the probe result.'

      def errors
        object.errors.full_messages
      end

      def details
        object.details.as_json
      end
    end
  end
end
# rubocop: enable Graphql/AuthorizeTypes
