# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Utils
        class ChatAuthorizer < Gitlab::Llm::Utils::Authorizer
          def self.context(context:)
            unless context.current_user
              return Response.new(allowed: false,
                message: no_access_message)
            end

            if context.resource && context.container
              authorization_container = container(container: context.container, user: context.current_user)
              if authorization_container.allowed?
                resource(resource: context.resource, user: context.current_user, context: context)
              else
                authorization_container
              end
            elsif context.resource
              resource(resource: context.resource, user: context.current_user, context: context)
            elsif context.container
              container(container: context.container, user: context.current_user)
            else
              user(user: context.current_user)
            end
          end

          def self.container(container:, user:)
            response = super(container: container, user: user)
            return response unless response.allowed?

            user(user: user)
          end

          def self.resource(resource:, user:, context: nil)
            # Check if we're in a merge request review context and the resource is confidential
            if merge_request_review_context?(context) && confidential_resource?(resource)
              return Response.new(allowed: false, message: not_found_message)
            end

            # Fall back to the parent class implementation for normal authorization
            super(resource: resource, user: user)
          end

          def self.user(user:)
            response = super(user: user)
            return response unless response.allowed?

            allowed = Ability.allowed?(user, :access_duo_entry_point)
            message = no_access_message unless allowed
            Response.new(allowed: allowed, message: message)
          end

          private_class_method def self.merge_request_review_context?(context)
            return false unless context

            # Check if we're in a Duo Code Review context
            context.instance_variable_get(:@is_duo_code_review) == true
          end

          private_class_method def self.confidential_resource?(resource)
            return false unless resource

            # Check if the resource has a confidential? method and is confidential
            resource.respond_to?(:confidential?) && resource.confidential?
          end
        end
      end
    end
  end
end
