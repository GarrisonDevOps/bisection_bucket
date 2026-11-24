# frozen_string_literal: true

module Namespaces
  module Storage
    class NamespaceLimitMailerPreview < ActionMailer::Preview
      def out_of_storage
        NamespaceLimitMailer.notify_out_of_storage(
          namespace: Group.last,
          recipients: %w[bob@example.com],
          usage_values: {
            current_size: 101.megabytes,
            limit: 100.megabytes,
            usage_ratio: 1.01
          })
      end

      def limit_warning
        NamespaceLimitMailer.notify_limit_warning(
          namespace: Group.last,
          recipients: %w[bob@example.com],
          usage_values: {
            current_size: 74.megabytes,
            limit: 100.megabytes,
            usage_ratio: 0.74
          })
      end
    end
  end
end
