# frozen_string_literal: true

module Namespaces
  module Storage
    module NamespaceLimit
      class PreEnforcementAlertComponent < ViewComponent::Base
        include ActiveSupport::NumberHelper
        include SafeFormatHelper
        include ::Namespaces::CombinedStorageUsers::PreEnforcement

        # @param [UserNamespace, Group, SubGroup, Project] context
        # @param [User] user
        def initialize(context:, user:)
          @context = context
          @root_namespace = context.root_ancestor
          @user = user
        end

        def render?
          return false unless user_allowed?
          return false if qualifies_for_combined_alert?

          over_storage_limit?(root_namespace)
        end

        private

        delegate :storage_counter, to: :helpers
        attr_reader :context, :root_namespace, :user

        def qualifies_for_combined_alert?
          over_user_limit?(root_namespace)
        end

        def storage_limit_docs_link
          help_page_path('user/storage_usage_quotas.md', anchor: 'manage-storage-usage')
        end

        def learn_more_link
          help_page_path('user/storage_usage_quotas.md', anchor: 'manage-storage-usage')
        end

        def strong_tags
          tag_pair(content_tag(:strong), :strong_start, :strong_end)
        end

        def paragraph_1_extra_message
          ''
        end

        def text_paragraph_1
          text_args = {
            namespace_name: root_namespace.name,
            extra_message: paragraph_1_extra_message,
            limit: dashboard_limit,
            **tag_pair(link_to('', storage_limit_docs_link), :storage_limit_link_start, :link_end),
            **strong_tags
          }

          safe_format(
            s_(
              "UsageQuota|%{storage_limit_link_start}A namespace storage limit%{link_end} of %{limit} will soon " \
                "be enforced for the %{strong_start}%{namespace_name}%{strong_end} namespace. %{extra_message}"
            ),
            text_args
          )
        end

        def dashboard_limit
          limit = Namespaces::Storage::RootSize.new(root_namespace).dashboard_limit

          number_to_human_size(limit, delimiter: ',', precision: 2)
        end

        def usage_quotas_nav_instruction
          message = if root_namespace.user_namespace?
                      s_("UsageQuota|User settings %{gt} Usage quotas")
                    else
                      s_("UsageQuota|Group settings %{gt} Usage quotas")
                    end

          safe_format(message, { gt: "&gt;".html_safe })
        end

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
                "of namespace storage. Group owners can view namespace storage usage and purchase more from " \
                "%{strong_start}%{usage_quotas_nav_instruction}%{strong_end}. " \
                "%{docs_link_start}How can I manage my storage%{link_end}?" \
            ),
            text_args
          )
        end

        def user_allowed?
          Ability.allowed?(user, :read_limit_alert, context)
        end

        def callout_feature_name
          "namespace_storage_pre_enforcement_banner"
        end

        def ignore_dismissal_earlier_than
          14.days.ago
        end

        def dismissible_alert_component
          Users::GroupDismissibleAlertComponent.new(
            variant: :warning,
            alert_options: alert_options,
            wrapper_options: wrapper_options,
            dismiss_options: dismiss_options
          )
        end

        def alert_options
          {
            data: { testid: 'storage-pre-enforcement-alert' }
          }
        end

        def wrapper_options
          { class: 'gl-mt-3' }
        end

        def dismiss_options
          {
            user: user,
            group: root_namespace,
            feature_id: callout_feature_name,
            ignore_dismissal_earlier_than: ignore_dismissal_earlier_than,
            defer_links: true
          }
        end
      end
    end
  end
end
