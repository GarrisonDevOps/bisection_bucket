# frozen_string_literal: true

module Namespaces
  module FreeUserCap
    class NotifyOverLimitService
      ServiceError = Class.new(StandardError)

      def self.execute(root_namespace)
        new(root_namespace).execute
      end

      def initialize(root_namespace)
        @root_namespace = root_namespace.root_ancestor
      end

      def execute
        notify

        Gitlab::AppLogger.info(
          class: self.class.name,
          namespace_id: root_namespace.id,
          message: 'Notifying owners of overage'
        )

        ServiceResponse.success
      rescue StandardError => e
        ServiceResponse.error(message: e.message)
      end

      private

      attr_reader :root_namespace

      def notify
        root_namespace.each_member_user(access_level: GroupMember::OWNER) do |owner|
          ::Namespaces::FreeUserCapMailer.over_limit_email(owner, root_namespace).deliver_now
        end
      end
    end
  end
end
