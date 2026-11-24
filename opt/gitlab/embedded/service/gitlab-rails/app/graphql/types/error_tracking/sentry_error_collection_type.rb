# frozen_string_literal: true

module Types
  module ErrorTracking
    class SentryErrorCollectionType < ::Types::BaseObject
      graphql_name 'SentryErrorCollection'
      description 'An object containing a collection of Sentry errors, and a detailed error'

      authorize :read_sentry_issue

      field :detailed_error,
        description: "Detailed version of a Sentry error on the project. #{SentryFieldCallLimit.description(1)}",
        resolver: Resolvers::ErrorTracking::SentryDetailedErrorResolver
      field :error_stack_trace,
        description: "Stack Trace of Sentry Error. #{SentryFieldCallLimit.description(1)}",
        resolver: Resolvers::ErrorTracking::SentryErrorStackTraceResolver
      field :errors,
        description: "Collection of Sentry Errors. #{SentryFieldCallLimit.description(2)}",
        resolver: Resolvers::ErrorTracking::SentryErrorsResolver,
        connection_extension: Gitlab::Graphql::Extensions::ExternallyPaginatedArrayExtension
      field :external_url,
        GraphQL::Types::String,
        null: true,
        description: "External URL for Sentry."
    end
  end
end
