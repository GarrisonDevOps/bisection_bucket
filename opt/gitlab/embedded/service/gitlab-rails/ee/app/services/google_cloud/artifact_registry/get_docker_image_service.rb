# frozen_string_literal: true

module GoogleCloud
  module ArtifactRegistry
    class GetDockerImageService < ::GoogleCloud::ArtifactRegistry::BaseProjectService
      NO_NAME_ERROR_RESPONSE = ServiceResponse.error(message: 'Name parameter is blank')

      private

      def call_client
        return NO_NAME_ERROR_RESPONSE unless valid_name?

        ServiceResponse.success(payload: client.docker_image(name: name))
      end

      def valid_name?
        name.present?
      end

      def name
        params[:name]
      end
    end
  end
end
