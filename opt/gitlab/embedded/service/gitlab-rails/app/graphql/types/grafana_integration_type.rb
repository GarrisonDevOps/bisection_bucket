# frozen_string_literal: true

# Deprecated:
#   Remove alongside query during any major release.
#   https://gitlab.com/gitlab-org/gitlab/-/issues/560601
module Types
  # rubocop:disable Graphql/AuthorizeTypes -- Project.grafanaIntegration always returns null, so this type is never resolved
  class GrafanaIntegrationType < ::Types::BaseObject
    graphql_name 'GrafanaIntegration'

    field :created_at, Types::TimeType, null: false,
      description: 'Timestamp of the issue\'s creation.'
    field :enabled, GraphQL::Types::Boolean, null: false,
      description: 'Indicates whether Grafana integration is enabled.'
    field :grafana_url, GraphQL::Types::String, null: false,
      description: 'URL for the Grafana host for the Grafana integration.'
    field :id, GraphQL::Types::ID, null: false,
      description: 'Internal ID of the Grafana integration.'
    field :updated_at, Types::TimeType, null: false,
      description: 'Timestamp of the issue\'s last activity.'
  end
  # rubocop:enable Graphql/AuthorizeTypes
end
