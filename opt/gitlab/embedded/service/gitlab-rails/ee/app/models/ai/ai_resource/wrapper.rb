# frozen_string_literal: true

module Ai
  module AiResource
    class Wrapper
      def initialize(user, resource)
        @user = user
        @resource = resource
      end

      def wrap
        resource_wrapper_class = "Ai::AiResource::#{resource.class}".safe_constantize
        # We need to implement it for all models we want to take into considerations
        raise ArgumentError, "#{resource.class} is not a valid AiResource class" unless resource_wrapper_class

        return unless resource_authorized?

        resource_wrapper_class.new(user, resource)
      end

      private

      attr_reader :user, :resource

      def resource_authorized?
        ::Gitlab::Llm::Chain::Utils::ChatAuthorizer.resource(resource: resource, user: user).allowed?
      end
    end
  end
end
