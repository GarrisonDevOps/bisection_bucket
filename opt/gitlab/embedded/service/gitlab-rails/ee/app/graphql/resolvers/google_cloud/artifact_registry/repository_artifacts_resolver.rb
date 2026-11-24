# frozen_string_literal: true

module Resolvers
  module GoogleCloud
    module ArtifactRegistry
      class RepositoryArtifactsResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        type ::Types::GoogleCloud::ArtifactRegistry::ArtifactType.connection_type, null: true

        argument :sort, Types::GoogleCloud::ArtifactRegistry::ArtifactsSortEnum,
          description: 'Criteria to sort artifacts by.',
          required: false,
          default_value: nil

        alias_method :project, :object

        def resolve(first: nil, last: nil, before: nil, after: nil, sort: nil) # rubocop:disable Lint/UnusedMethodArgument -- Required GraphQL arguments for Connections
          response = list_docker_images_service(first: first, after: after, sort: sort).execute

          raise_resource_not_available_error!(response.message) unless response.success?

          Gitlab::Graphql::ExternallyPaginatedArray.new(
            after,
            response.payload.next_page_token,
            *response.payload.docker_images
          )
        end

        private

        def list_docker_images_service(params)
          ::GoogleCloud::ArtifactRegistry::ListDockerImagesService.new(
            project: project,
            current_user: current_user,
            params: {
              page_size: params[:first],
              page_token: params[:after],
              order_by: params[:sort]
            }
          )
        end
      end
    end
  end
end
