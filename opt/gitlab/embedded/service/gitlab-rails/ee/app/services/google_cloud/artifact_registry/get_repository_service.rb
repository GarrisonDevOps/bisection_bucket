# frozen_string_literal: true

module GoogleCloud
  module ArtifactRegistry
    class GetRepositoryService < ::GoogleCloud::ArtifactRegistry::BaseProjectService
      private

      def call_client
        ServiceResponse.success(payload: client.repository)
      end
    end
  end
end
