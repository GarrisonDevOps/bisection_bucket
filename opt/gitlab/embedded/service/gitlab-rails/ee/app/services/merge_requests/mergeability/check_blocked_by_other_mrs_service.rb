# frozen_string_literal: true

module MergeRequests
  module Mergeability
    class CheckBlockedByOtherMrsService < CheckBaseService
      set_identifier :merge_request_blocked
      set_failure_explanation N_('All merge requests that block this one must be merged.')
      set_description 'Checks whether the merge request is blocked'

      def execute
        return inactive unless merge_request.blocking_merge_requests_feature_available?

        if merge_request.merge_blocked_by_other_mrs?
          failure
        else
          success
        end
      end

      def skip?
        params[:skip_blocked_check].present?
      end

      def cacheable?
        false
      end
    end
  end
end
