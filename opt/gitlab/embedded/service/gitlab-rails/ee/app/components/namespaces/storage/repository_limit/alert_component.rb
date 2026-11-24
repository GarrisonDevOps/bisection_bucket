# frozen_string_literal: true

module Namespaces
  module Storage
    module RepositoryLimit
      class AlertComponent < BaseAlertComponent
        include Gitlab::Utils::StrongMemoize

        HIGH_LIMIT_WARNING_CACHE_EXPIRY = 10.minutes

        private

        def render?
          return true if show_approaching_high_limit_message?
          return false if context.is_a?(Group) && !current_page?(group_usage_quotas_path(context))
          return false if context.is_a?(Project) && context.repository_size_excess == 0

          super
        end

        def alert_title
          return super unless show_approaching_high_limit_message?

          safe_format(
            s_(
              "NamespaceStorageSize|We've noticed an unusually high storage usage on %{namespace_name}"
            ),
            { namespace_name: root_namespace.name }
          )
        end

        def default_alert_title
          text_args = {
            readonly_project_count: root_namespace.repository_size_excess_project_count,
            namespace_name: root_namespace.name
          }

          ns_(
            "NamespaceStorageSize|%{namespace_name} has " \
              "%{readonly_project_count} read-only project",
            "NamespaceStorageSize|%{namespace_name} has " \
              "%{readonly_project_count} read-only projects",
            text_args[:readonly_project_count]
          ) % text_args
        end

        def usage_percentage_alert_title
          text_args = {
            usage_in_percent: used_storage_percentage(root_storage_size.usage_ratio),
            namespace_name: root_namespace.name
          }

          if root_storage_size.above_size_limit?
            default_alert_title
          else
            s_(
              "NamespaceStorageSize|You have used %{usage_in_percent} of the purchased storage for %{namespace_name}"
            ) % text_args
          end
        end

        def free_tier_alert_title
          text_args = {
            readonly_project_count: root_namespace.repository_size_excess_project_count,
            free_size_limit: formatted(limit)
          }

          if root_namespace.paid?
            default_alert_title
          else
            ns_(
              "NamespaceStorageSize|You have reached the free storage limit of %{free_size_limit} on " \
                "%{readonly_project_count} project",
              "NamespaceStorageSize|You have reached the free storage limit of %{free_size_limit} on " \
                "%{readonly_project_count} projects",
              text_args[:readonly_project_count]
            ) % text_args
          end
        end

        def alert_message
          manage_storage_link = help_page_path('user/storage_usage_quotas.md', anchor: 'manage-storage-usage')
          return super unless show_approaching_high_limit_message?

          [
            safe_format(
              s_(
                "NamespaceStorageSize|To manage your usage and prevent your projects " \
                  "from being placed in a read-only state, you should immediately " \
                  "%{manage_storage_link_start}reduce storage%{link_end}, or " \
                  "%{support_link_start}contact support%{link_end} to help you manage your usage."
              ),
              {
                **tag_pair(link_to('', manage_storage_link), :manage_storage_link_start, :link_end),
                **tag_pair(link_to('', Gitlab::Saas.customer_support_url), :support_link_start, :link_end)
              }
            )
          ]
        end

        def alert_message_explanation
          text_args = {
            free_size_limit: formatted(limit),
            **tag_pair(link_to('', storage_docs_link), :storage_docs_link_start, :link_end)
          }

          if root_storage_size.above_size_limit?
            safe_format(
              s_(
                "NamespaceStorageSize|You have consumed all available " \
                  "%{storage_docs_link_start}storage%{link_end} and can't " \
                  "push or add large files to projects over the included storage (%{free_size_limit})."
              ),
              text_args
            )
          else
            safe_format(
              s_(
                "NamespaceStorageSize|When a project reaches 100%% of the " \
                  "%{storage_docs_link_start}allocated storage%{link_end} (%{free_size_limit}) it will be placed " \
                  "in a read-only state. You won't be able to push and add large files to your repository."
              ),
              text_args
            )
          end
        end

        def alert_message_cta
          group_member_link = group_group_members_path(root_namespace)
          purchase_more_link = help_page_path('user/storage_usage_quotas.md', anchor: 'purchase-more-storage')
          manage_storage_link = help_page_path('user/storage_usage_quotas.md', anchor: 'manage-storage-usage')
          text_args = {
            **tag_pair(link_to('', group_member_link), :group_member_link_start, :link_end),
            **tag_pair(link_to('', purchase_more_link), :purchase_more_link_start, :link_end),
            **tag_pair(link_to('', manage_storage_link), :manage_storage_link_start, :link_end),
            **tag_pair(link_to('', Gitlab::Saas.customer_support_url), :support_link_start, :link_end)
          }

          unless root_storage_size.above_size_limit?
            return s_("NamespaceStorageSize|To reduce storage usage, reduce git repository and git LFS storage.")
          end

          if root_storage_size.subject_to_high_limit?
            return safe_format(
              s_(
                "NamespaceStorageSize|To remove the read-only state, " \
                  "%{manage_storage_link_start}manage your storage usage%{link_end} " \
                  "or %{support_link_start}contact support%{link_end}."
              ),
              text_args
            )
          end

          if Ability.allowed?(user, :admin_namespace, context)
            return safe_format(
              s_(
                "NamespaceStorageSize|To remove the read-only state, " \
                  "%{manage_storage_link_start}manage your storage usage%{link_end} " \
                  "or %{purchase_more_link_start}purchase more storage%{link_end}."
              ),
              text_args
            )
          end

          safe_format(
            s_(
              "NamespaceStorageSize|To remove the read-only state " \
                "contact a user with the %{group_member_link_start}owner role for this namespace%{link_end} " \
                "and ask them to %{purchase_more_link_start}purchase more storage%{link_end}."
            ),
            text_args
          )
        end

        def usage_thresholds
          return DEFAULT_USAGE_THRESHOLDS if namespace_has_additional_storage_purchased?

          DEFAULT_USAGE_THRESHOLDS.except(:warning, :alert)
        end

        def alert_level
          return :warning if show_approaching_high_limit_message?

          super
        end

        def show_purchase_link?
          return false if root_storage_size.subject_to_high_limit?

          super
        end

        def limit
          root_namespace.actual_size_limit
        end

        def show_approaching_high_limit_message?
          return false unless root_storage_size.subject_to_high_limit?

          Rails.cache.fetch(
            ['namespaces', root_namespace.id, 'repository_limit_high_limit_warning'],
            expires_in: HIGH_LIMIT_WARNING_CACHE_EXPIRY
          ) do
            !root_storage_size.above_size_limit? &&
              root_storage_size.has_projects_over_high_limit_warning_threshold?
          end
        end
        strong_memoize_attr :show_approaching_high_limit_message?
      end
    end
  end
end
