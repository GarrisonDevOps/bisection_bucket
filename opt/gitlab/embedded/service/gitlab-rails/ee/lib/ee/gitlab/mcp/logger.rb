# frozen_string_literal: true

module EE
  module Gitlab
    module Mcp
      module Logger
        extend ::Gitlab::Utils::Override

        private

        # The instance setting takes precedence so self-hosted Duo instances can opt in without the
        # :expanded_ai_logging flag, which is intended for gitlab.com only.
        override :should_log_expanded?
        def should_log_expanded?(user, namespace: nil)
          return true if ::Gitlab::CurrentSettings.enabled_expanded_logging
          return true if ::Feature.enabled?(:expanded_ai_logging, user)
          return false unless namespace

          namespace.ai_usage_data_collection_enabled
        end
      end
    end
  end
end
