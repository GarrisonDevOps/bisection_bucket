# frozen_string_literal: true

module Users
  module Abuse
    module NamespaceBans
      class CreateService < BaseService
        attr_accessor :user, :namespace

        def initialize(user:, namespace:, current_user: nil)
          @current_user = current_user
          @user = user
          @namespace = namespace
        end

        def execute
          ban = ::Namespaces::NamespaceBan.new(user: user, namespace: namespace)

          if ban.save
            log_audit_event(user, namespace)
            ServiceResponse.success
          else
            messages = ban.errors.full_messages
            ServiceResponse.error(message: messages.uniq.join('. '))
          end
        end

        private

        def event_name
          'namespace_ban_created'
        end

        def event_message
          'Banned user'
        end
      end
    end
  end
end
