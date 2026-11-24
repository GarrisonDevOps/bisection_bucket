# frozen_string_literal: true

module Ai
  module CustomizablePermission
    extend ActiveSupport::Concern

    def ai_minimum_access_level_execute_with_fallback
      resolve_ai_settings&.minimum_access_level_execute
    end

    def ai_minimum_access_level_execute_async_with_fallback
      resolve_ai_settings&.minimum_access_level_execute_async || ::Gitlab::Access::DEVELOPER
    end

    private

    def resolve_ai_settings
      gitlab_com? ? root_ancestor.ai_settings : Ai::Setting.for_organization_read_only(root_ancestor.organization)
    end

    def gitlab_com?
      ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
    end
  end
end
