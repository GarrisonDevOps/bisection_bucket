# frozen_string_literal: true

module Types
  module Ci
    class ProjectSubscriptionType < BaseObject
      graphql_name 'CiProjectSubscription'

      connection_type_class Types::CountableConnectionType

      authorize :read_project_subscription

      field :id, Types::GlobalIDType[::Ci::Subscriptions::Project], description: "Global ID of the subscription."

      field :downstream_project, Types::Ci::Subscriptions::ProjectDetailsType,
        description: "Downstream project of the subscription." \
          "When an upstream project's pipeline completes, a pipeline is triggered " \
          "in the downstream project."

      field :upstream_project, Types::Ci::Subscriptions::ProjectDetailsType,
        description: "Upstream project of the subscription." \
          "When an upstream project's pipeline completes, a pipeline is triggered " \
          "in the downstream project."

      field :author, Types::UserType, description: "Author of the subscription."
    end
  end
end
