# frozen_string_literal: true

module Cd
  module Versions
    class CreateService
      def initialize(artifact_source:, current_user: nil, params: {})
        @artifact_source = artifact_source
        @current_user = current_user
        @params = params
      end

      def execute
        version = artifact_source.versions.build(name: params[:name], verified: params.fetch(:verified, false))

        return ServiceResponse.success(payload: { version: version }) if version.save

        ServiceResponse.error(message: version.errors.full_messages, payload: { version: version })
      end

      private

      attr_reader :artifact_source, :current_user, :params
    end
  end
end
