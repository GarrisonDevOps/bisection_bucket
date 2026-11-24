# frozen_string_literal: true

module EE
  module Namespaces
    module RootStatisticsWorker
      extend ::Gitlab::Utils::Override

      private

      override :notify_storage_usage
      def notify_storage_usage(namespace)
        ::Namespaces::Storage::NamespaceLimit::EmailNotificationService.execute(namespace)
      end
    end
  end
end
