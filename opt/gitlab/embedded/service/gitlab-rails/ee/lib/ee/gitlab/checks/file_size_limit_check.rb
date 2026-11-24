# frozen_string_literal: true

module EE
  module Gitlab
    module Checks
      module FileSizeLimitCheck
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        LOG_MESSAGE = 'Checking for blobs over the file size limit'

        override :validate!
        def validate!
          limit = file_size_limit
          return unless limit.present?

          ::Gitlab::AppJsonLogger.info(LOG_MESSAGE)
          logger.log_timed(LOG_MESSAGE) do
            oversized_blobs = ::Gitlab::Checks::FileSizeCheck::HookEnvironmentAwareAnyOversizedBlobs.new(
              project: project,
              changes: changes,
              file_size_limit_megabytes: limit
            ).find

            if oversized_blobs.present?
              blob_id_size_msg = oversized_blobs.map do |blob|
                "- #{blob.id} (#{number_to_human_size(blob.size)})"
              end.join("\n")

              oversize_err_msg = <<~OVERSIZE_ERR_MSG
                You are attempting to check in one or more blobs which exceed the #{limit}MiB limit:

                #{blob_id_size_msg}

                To resolve this error, you must either reduce the size of the above blobs, or utilize LFS.
                You may use "git ls-tree -r HEAD | grep $BLOB_ID" to see the file path.

                Please refer to #{error_link} for further information.
              OVERSIZE_ERR_MSG

              ::Gitlab::AppJsonLogger.info(
                message: 'Found blob over global limit',
                blob_details: oversized_blobs.map { |blob| { "id" => blob.id, "size" => blob.size } }
              )

              raise ::Gitlab::GitAccess::ForbiddenError, oversize_err_msg
            end
          end

          true
        end

        private

        override :file_size_limit
        def file_size_limit
          return plan_limit if use_plan_limit?

          push_rule_limit
        end

        def use_plan_limit?
          return true if push_rule_limit == 0
          return false if plan_limit.nil?

          true if plan_limit <= push_rule_limit
        end

        def push_rule_limit
          push_rule&.max_file_size.to_i
        end

        def plan_limit
          return unless ::Gitlab::Saas.feature_available?(:instance_push_limit)

          project.actual_limits.file_size_limit_mb
        end

        def error_link
          if use_plan_limit?
            plan_limit_error_link
          else
            push_rule_limit_error_link
          end
        end

        def push_rule_limit_error_link
          "https://docs.gitlab.com/user/project/repository/push_rules/#validate-files"
        end

        def plan_limit_error_link
          "#{Rails.application.routes.url_helpers.help_page_url('user/free_push_limit.md')} and
          #{Rails.application.routes.url_helpers.help_page_url(
            'administration/settings/account_and_limit_settings.md')}"
        end
      end
    end
  end
end
