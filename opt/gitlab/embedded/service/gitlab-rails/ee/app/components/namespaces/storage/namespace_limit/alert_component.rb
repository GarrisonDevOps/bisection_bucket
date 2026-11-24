# frozen_string_literal: true

module Namespaces
  module Storage
    module NamespaceLimit
      class AlertComponent < BaseAlertComponent
        private

        def render?
          return false unless ::Gitlab::Saas.feature_available?(:namespaces_storage_limit)
          return false if hide_threshold_banner?

          super
        end

        def hide_threshold_banner?
          alert_level.in?(%i[warning alert]) &&
            Enforcement.in_enforcement_rollout?(root_namespace)
        end

        def limit
          root_storage_size.dashboard_limit
        end

        def free_tier_alert_title
          text_args = {
            namespace_name: root_namespace.name,
            free_size_limit: formatted(limit)
          }

          s_(
            "NamespaceStorageSize|You have reached the free storage limit of %{free_size_limit} for %{namespace_name}"
          ) % text_args
        end

        def usage_percentage_alert_title
          text_args = {
            usage_in_percent: used_storage_percentage(root_storage_size.usage_ratio),
            namespace_name: root_namespace.name,
            used_storage: formatted(root_storage_size.current_size),
            storage_limit: formatted(limit)
          }

          s_(
            "NamespaceStorageSize|You have used %{usage_in_percent} of the storage quota for %{namespace_name} " \
              "(%{used_storage} of %{storage_limit})"
          ) % text_args
        end

        def alert_message_explanation
          text_args = {
            namespace_name: root_namespace.name,
            **tag_pair(link_to('', help_page_path('user/read_only_namespaces.md')), :read_only_link_start, :link_end),
            **tag_pair(link_to('', storage_docs_link), :storage_docs_link_start, :link_end)
          }

          if root_storage_size.above_size_limit?
            safe_format(
              s_(
                "NamespaceStorageSize|%{namespace_name} is now read-only. Your ability to write new data to " \
                  "this namespace is restricted. %{read_only_link_start}Which actions are restricted?%{link_end}"
              ),
              text_args
            )
          else
            safe_format(
              s_(
                "NamespaceStorageSize|If %{namespace_name} exceeds the " \
                  "%{storage_docs_link_start}storage quota%{link_end}, your ability to " \
                  "write new data to this namespace will be restricted. " \
                  "%{read_only_link_start}Which actions become restricted?%{link_end}"
              ),
              text_args
            )
          end
        end

        def alert_message_cta
          manage_storage_link = help_page_path('user/storage_usage_quotas.md', anchor: 'manage-storage-usage')
          group_member_link = group_group_members_path(root_namespace)
          purchase_more_link = help_page_path('user/storage_usage_quotas.md', anchor: 'purchase-more-storage')
          text_args = {
            **tag_pair(link_to('', manage_storage_link), :manage_storage_link_start, :link_end),
            **tag_pair(link_to('', group_member_link), :group_member_link_start, :link_end),
            **tag_pair(link_to('', purchase_more_link), :purchase_more_link_start, :link_end)
          }

          if root_storage_size.above_size_limit?
            if Ability.allowed?(user, :admin_namespace, context)
              return safe_format(
                s_(
                  "NamespaceStorageSize|To remove the read-only state " \
                    "%{manage_storage_link_start}manage your storage usage%{link_end}, " \
                    "or %{purchase_more_link_start}purchase more storage%{link_end}."
                ),
                text_args
              )
            end

            safe_format(
              s_(
                "NamespaceStorageSize|To remove the read-only state " \
                  "%{manage_storage_link_start}manage your storage usage%{link_end}, " \
                  "or contact a user with the %{group_member_link_start}owner role for this namespace%{link_end} " \
                  "and ask them to %{purchase_more_link_start}purchase more storage%{link_end}."
              ),
              text_args
            )
          else
            if Ability.allowed?(user, :admin_namespace, context)
              return safe_format(
                s_(
                  "NamespaceStorageSize|To prevent your projects from being in a read-only state " \
                    "%{manage_storage_link_start}manage your storage usage%{link_end}, " \
                    "or %{purchase_more_link_start}purchase more storage%{link_end}."
                ),
                text_args
              )
            end

            safe_format(
              s_(
                "NamespaceStorageSize|To prevent your projects from being in a read-only state " \
                  "%{manage_storage_link_start}manage your storage usage%{link_end}, " \
                  "or contact a user with the %{group_member_link_start}owner role for this namespace%{link_end} " \
                  "and ask them to %{purchase_more_link_start}purchase more storage%{link_end}."
              ),
              text_args
            )
          end
        end
      end
    end
  end
end
