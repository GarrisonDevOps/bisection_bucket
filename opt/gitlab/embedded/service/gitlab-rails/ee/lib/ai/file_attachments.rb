# frozen_string_literal: true

module Ai
  module FileAttachments
    # The flag gates everything. Elsewhere than GitLab.com, the instance setting decides.
    def self.allowed?(namespace, user:) # rubocop:disable Lint/UnusedMethodArgument -- used again by the TODO below
      return false unless ::Feature.enabled?(:dap_web_chat_file_attachments, user)

      if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) # rubocop:disable Style/RedundantCondition -- temporary, see TODO
        # TODO: return the group setting once admins can set it (https://gitlab.com/gitlab-org/gitlab/-/merge_requests/268362).
        # https://gitlab.com/gitlab-org/gitlab/-/merge_requests/269571 restores this check.
        # !!namespace&.root_ancestor&.duo_workflow_file_attachments_enabled
        true
      else
        ::Ai::Setting.for_current_or_default_organization.duo_workflow_file_attachments_enabled
      end
    end
  end
end
