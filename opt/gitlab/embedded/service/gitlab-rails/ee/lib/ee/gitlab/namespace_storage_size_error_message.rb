# frozen_string_literal: true

module EE
  module Gitlab
    class NamespaceStorageSizeErrorMessage
      include SafeFormatHelper
      include ActiveSupport::NumberHelper

      delegate :current_size, :limit, :exceeded_size, to: :@checker

      def initialize(checker:, message_params: {})
        @checker = checker
        @message_params = message_params
      end

      def commit_error
        _(
          "Your action has been rejected because the namespace storage limit has been reached. " \
          "For more information, visit %{doc_url}.") % {
            doc_url: ::Gitlab::Routing.url_helpers.help_page_url('user/storage_usage_quotas.md')
          }
      end

      def merge_error
        _("Your namespace storage is full. This merge request cannot be merged.")
      end

      def push_warning
        _(
          "##### WARNING ##### You have used %{usage_percentage} of the storage quota for %{namespace_name} " \
          "(%{current_size} of %{size_limit}). If %{namespace_name} exceeds the storage quota, " \
          "all projects in the namespace will be locked and actions will be restricted. " \
          "To manage storage, or purchase additional storage, see %{manage_storage_url}. " \
          "To learn more about restricted actions, see %{restricted_actions_url}"
        ) % push_message_params
      end

      def push_error(_change_size = 0)
        _(
          "##### ERROR ##### You have used %{usage_percentage} of the storage quota for %{namespace_name} " \
          "(%{current_size} of %{size_limit}). %{namespace_name} is now read-only. " \
          "Projects under this namespace are locked and actions will be restricted. " \
          "To manage storage, or purchase additional storage, see %{manage_storage_url}. " \
          "To learn more about restricted actions, see %{restricted_actions_url}"
        ) % push_message_params
      end

      def new_changes_error
        _(
          "Your push to this repository has been rejected because it would exceed " \
          "the namespace storage limit of %{size_limit}. " \
          "Reduce your namespace storage or purchase additional storage." \
          "To manage storage, or purchase additional storage, see %{manage_storage_url}. " \
          "To learn more about restricted actions, see %{restricted_actions_url}"
        ) % push_message_params
      end

      def above_size_limit_message
        format(
          _(
            "The namespace storage size (%{current_size}) exceeds the limit of %{size_limit} " \
            "by %{exceeded_size}. You won't be able to push new code to this project. " \
            "Please contact your GitLab administrator for more information."
          ),
          current_size: formatted(current_size),
          size_limit: formatted(limit),
          exceeded_size: formatted(exceeded_size)
        )
      end

      private

      attr_reader :message_params

      def push_message_params
        {
          namespace_name: message_params[:namespace_name],
          manage_storage_url: ::Gitlab::Routing.url_helpers.help_page_url('user/storage_usage_quotas.md',
            anchor: 'manage-storage-usage'),
          restricted_actions_url: ::Gitlab::Routing.url_helpers.help_page_url('user/read_only_namespaces.md',
            anchor: 'restricted-actions'),
          current_size: formatted(current_size),
          size_limit: formatted(limit),
          usage_percentage: usage_percentage
        }
      end

      def formatted(number)
        number_to_human_size(number, delimiter: ',', precision: 2)
      end

      def usage_percentage
        number_to_percentage(@checker.usage_ratio * 100, precision: 0)
      end

      def link_to(text, url, options)
        ActionController::Base.helpers.link_to(text, url, options)
      end
    end
  end
end
