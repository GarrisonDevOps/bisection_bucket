# frozen_string_literal: true

module Resolvers
  module Notifications
    class TargetedMessageResolver < BaseResolver
      type [Types::Notifications::TargetedMessageType], null: true
      description 'Targeted messages for the namespace.'

      authorize :read_namespace

      alias_method :namespace, :object

      def resolve
        return unless current_user

        user_access_level = namespace.max_member_access_for_user(current_user)

        ::Notifications::TargetedMessageNamespace
          .by_namespace_for_user(namespace, current_user)
          .map(&:targeted_message)
          .select { |message| message.matches_current_user_access_level?(user_access_level) }
      end
    end
  end
end
