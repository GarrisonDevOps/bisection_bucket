# frozen_string_literal: true

module EE
  module Emails
    module MergeRequests
      def added_as_approver_email(recipient_id, merge_request_id, updated_by_user_id, reason = nil)
        setup_merge_request_mail(merge_request_id, recipient_id)

        mail_answer_thread(@merge_request, merge_request_thread_options(updated_by_user_id, reason))
      end
    end
  end
end
