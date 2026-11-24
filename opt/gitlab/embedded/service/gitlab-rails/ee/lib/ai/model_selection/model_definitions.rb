# frozen_string_literal: true

module Ai
  module ModelSelection
    class ModelDefinitions
      def self.fetch(user = nil)
        new(::Ai::ModelSelection::FetchModelDefinitionsService.new(user).execute)
      end

      def initialize(service_response)
        @service_response = service_response
      end

      def success?
        !!@service_response&.success?
      end

      def error_message
        @service_response&.message
      end

      def payload
        return unless success?

        @service_response.payload
      end

      def parser
        return unless payload

        ::Gitlab::Ai::ModelSelection::ModelDefinitionResponseParser.new(payload)
      end
    end
  end
end
