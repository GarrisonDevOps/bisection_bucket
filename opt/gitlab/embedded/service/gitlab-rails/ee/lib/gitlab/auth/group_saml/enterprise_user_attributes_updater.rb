# frozen_string_literal: true

module Gitlab
  module Auth
    module GroupSaml
      class EnterpriseUserAttributesUpdater
        attr_reader :user, :group, :auth_hash

        def initialize(user, group, auth_hash)
          @user = user
          @group = group
          @auth_hash = auth_hash
        end

        def execute
          return unless auth_hash.user_attributes.any?
          return unless user.managed_by_group?(group)

          result = Users::UpdateService.new(user, auth_hash.user_attributes.merge(user: user)).execute

          log(result)

          result
        end

        private

        def log(result)
          Gitlab::AppLogger.info(
            Labkit::Fields::CLASS_NAME => self.class.name,
            Labkit::Fields::GL_USER_ID => user.id,
            group_id: group.id,
            message: log_message_for(result)
          )
        end

        def log_message_for(result)
          if result[:status] == :success
            'Updated the enterprise user attributes.'
          elsif result[:status] == :error
            "Failed to update the enterprise user attributes. #{result[:message]}."
          end
        end
      end
    end
  end
end
