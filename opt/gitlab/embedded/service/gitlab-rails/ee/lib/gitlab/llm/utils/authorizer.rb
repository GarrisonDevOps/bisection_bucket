# frozen_string_literal: true

module Gitlab
  module Llm
    module Utils
      class Authorizer
        include Gitlab::Llm::Concerns::Logger

        Response = Struct.new(:allowed, :message, keyword_init: true) do
          def allowed?
            allowed
          end
        end

        def self.container(container:, user:)
          return Response.new(allowed: false, message: not_found_message) unless container && user

          if Ability.allowed?(user, :access_duo_features, container)
            Response.new(allowed: true)
          else
            Response.new(allowed: false, message: container_not_allowed_message(container, user))
          end
        end

        def self.resource(resource:, user:)
          return Response.new(allowed: false, message: not_found_message) unless resource && user
          return user_as_resource(resource: resource, user: user) if resource.is_a?(User)

          allowed = Ability.allowed?(user, "read_#{resource.to_ability_name}", resource)

          return Response.new(allowed: false, message: not_found_message) unless allowed

          authorization_container = container(container: resource.resource_parent, user: user)

          return authorization_container unless authorization_container.allowed?

          Response.new(allowed: true)
        end

        # Child classes may impose additional restrictions
        def self.user(user:)
          Response.new(allowed: user.present?)
        end

        private_class_method def self.user_as_resource(resource:, user:)
          return Response.new(allowed: false, message: not_found_message) if user != resource

          user(user: user)
        end

        private_class_method def self.container_not_allowed_message(container, user)
          container.member?(user) ? no_ai_message : not_found_message
        end

        private_class_method def self.not_found_message
          log_info(message: "Resource not found",
            event_name: 'permission_denied',
            ai_component: 'abstraction_layer',
            ai_error_code: "M3003")
          s_("AI|I'm sorry, I can't generate a response. You might want to try again. " \
            "You could also be getting this error because the items you're asking about " \
            "either don't exist, you don't have access to them, or your session has expired.")
        end

        private_class_method def self.no_access_message
          s_("AI|I'm sorry, I can't generate a response. You do not have access to GitLab Duo Chat.")
        end

        private_class_method def self.no_ai_message
          log_info(message: "AI is disabled",
            event_name: 'permission_denied',
            ai_component: 'abstraction_layer',
            ai_error_code: "M3002")
          s_("AI|I am sorry, I cannot access the information you are asking about. " \
            "A group or project owner has turned off Duo features in this group or project.")
        end
      end
    end
  end
end
