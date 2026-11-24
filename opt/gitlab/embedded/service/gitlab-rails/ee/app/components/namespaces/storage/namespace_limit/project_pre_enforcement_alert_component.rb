# frozen_string_literal: true

module Namespaces
  module Storage
    module NamespaceLimit
      class ProjectPreEnforcementAlertComponent < PreEnforcementAlertComponent
        extend ::Gitlab::Utils::Override

        private

        override :paragraph_1_extra_message
        def paragraph_1_extra_message
          safe_format(
            s_("UsageQuota|The %{strong_start}%{context_name}%{strong_end} project will be affected by this. "),
            strong_tags.merge(context_name: context.name)
          )
        end

        override :dismissible_alert_component
        def dismissible_alert_component
          return super unless user_namespace?

          # This callout is used when user A is viewing a project that belongs to a User B
          # i.e. User B Namespace owns the project, and user A is a maintainer on given project
          # We can't use Users::Callout because we'd dismiss user A Namespace alert
          # So we rely on Users::ProjectCallout for proper dismissal without side effects
          Users::ProjectDismissibleAlertComponent.new(
            variant: :warning,
            alert_options: alert_options,
            wrapper_options: wrapper_options,
            dismiss_options: dismiss_options
          )
        end

        override :dismiss_options
        def dismiss_options
          return super unless user_namespace?

          {
            user: user,
            project: context,
            feature_id: callout_feature_name,
            ignore_dismissal_earlier_than: ignore_dismissal_earlier_than,
            defer_links: true
          }
        end

        def user_namespace?
          root_namespace.user_namespace?
        end
      end
    end
  end
end
