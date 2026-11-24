# frozen_string_literal: true

module Namespaces
  module Storage
    module NamespaceLimit
      class UserPreEnforcementAlertComponent < PreEnforcementAlertComponent
        extend ::Gitlab::Utils::Override

        private

        override :text_paragraph_2
        def text_paragraph_2
          text_args = {
            used_storage: storage_counter(root_namespace.root_storage_statistics&.storage_size || 0),
            usage_quotas_nav_instruction: usage_quotas_nav_instruction,
            **tag_pair(link_to('', learn_more_link), :docs_link_start, :link_end),
            **strong_tags
          }

          safe_format(
            s_(
              "UsageQuota|The namespace is currently using %{strong_start}%{used_storage}%{strong_end} " \
                "of namespace storage. View and manage your usage from " \
                "%{strong_start}%{usage_quotas_nav_instruction}%{strong_end}. " \
                "%{docs_link_start}Learn more%{link_end} about how to reduce your storage." \
            ),
            text_args
          )
        end

        override :user_allowed?
        def user_allowed?
          Ability.allowed?(user, :admin_namespace, context)
        end

        override :dismissible_alert_component
        def dismissible_alert_component
          Users::DismissibleAlertComponent.new(
            variant: :warning,
            alert_options: alert_options,
            wrapper_options: wrapper_options,
            dismiss_options: dismiss_options
          )
        end

        override :dismiss_options
        def dismiss_options
          {
            user: user,
            feature_id: callout_feature_name,
            ignore_dismissal_earlier_than: ignore_dismissal_earlier_than,
            defer_links: true
          }
        end
      end
    end
  end
end
