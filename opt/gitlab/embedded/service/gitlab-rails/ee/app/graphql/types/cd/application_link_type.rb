# frozen_string_literal: true

module Types
  module Cd
    class ApplicationLinkType < ::Types::BaseObject
      graphql_name 'CdApplicationLink'
      description 'Continuous deployment application link.'

      connection_type_class Types::CountableConnectionType

      authorize :read_cd_application_link
      authorize_granular_token permissions: :read_cd_application_link,
        boundaries: [
          { boundary: :instance, boundary_type: :instance }
        ]

      field :id, Types::GlobalIDType[::Cd::ApplicationLink],
        null: false,
        description: 'Global ID of the link.'

      field :name, GraphQL::Types::String,
        null: false,
        description: 'Name of the link.'

      field :url, GraphQL::Types::String,
        null: false,
        description: 'URL of the link.'

      field :link_type, ::Types::Cd::ApplicationLinkTypeEnum,
        null: false,
        description: 'Type of the link.'

      field :application, ::Types::Cd::ApplicationType,
        null: false,
        description: 'Application the link belongs to.'

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the link was created.'

      field :updated_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the link was last updated.'

      def application
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::Application, object.application_id).find
      end
    end
  end
end
