# frozen_string_literal: true

module Cd
  module ArtifactSources
    class CreateService
      def initialize(parent:, current_user: nil, params: {})
        @parent = parent
        @current_user = current_user
        @params = params.dup
      end

      def execute
        artifact_source = ::Cd::ArtifactSource.new(
          params.merge(service: parent, organization: parent.organization)
        )

        if artifact_source.save
          ::Cd::Versions::BackfillFromArtifactSourceWorker.perform_async(artifact_source.id)
          ServiceResponse.success(payload: { artifact_source: artifact_source })
        else
          ServiceResponse.error(
            message: artifact_source.errors.full_messages,
            payload: { artifact_source: artifact_source }
          )
        end
      end

      private

      attr_reader :parent, :current_user, :params
    end
  end
end
