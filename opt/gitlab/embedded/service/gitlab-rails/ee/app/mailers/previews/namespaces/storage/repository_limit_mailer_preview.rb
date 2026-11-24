# frozen_string_literal: true

module Namespaces
  module Storage
    class RepositoryLimitMailerPreview < ActionMailer::Preview
      def out_of_storage
        RepositoryLimitMailer.notify_out_of_storage(
          project_name: Project.last.name,
          recipients: %w[bob@example.com]
        )
      end

      def limit_warning
        RepositoryLimitMailer.notify_limit_warning(
          project_name: Project.last.name,
          recipients: %w[bob@example.com]
        )
      end
    end
  end
end
