# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class UploadRegistryType < BaseObject
      graphql_name 'UploadRegistry'
      description 'Represents the Geo replication and verification state of an upload.'

      include ::Types::Geo::RegistryType

      field :file_id, GraphQL::Types::ID, null: false, description: 'ID of the Upload.'

      # Rows from Geo::UploadPartitionRegistriesFinder carry the partition's replicable_name.
      def data_management_details_path
        return unless object.model_record_id

        model_name_plural =
          if object.has_attribute?(:replicable_name)
            ::Gitlab::Geo::Replicator.for_replicable_name(object.replicable_name).model_name_plural
          else
            object.class.replicator_class.model_name_plural
          end

        ::Gitlab::Routing.url_helpers.details_admin_data_management_path(
          model_name: model_name_plural,
          id: object.model_record_id
        )
      end
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
