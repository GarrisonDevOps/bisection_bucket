# frozen_string_literal: true

module Types
  module Ci
    module Subscriptions
      class ProjectType < BaseObject
        graphql_name 'CiSubscriptionsProject'

        connection_type_class Types::CountableConnectionType

        authorize :read_project_subscription

        field :id, Types::GlobalIDType[::Ci::Subscriptions::Project], description: "Global ID of the subscription."

        field :downstream_project, Types::ProjectType,
          description: "Downstream project of the subscription."

        field :upstream_project, Types::ProjectType,
          description: "Upstream project of the subscription."

        field :author, Types::UserType, description: "Author of the subscription."
      end
    end
  end
end
