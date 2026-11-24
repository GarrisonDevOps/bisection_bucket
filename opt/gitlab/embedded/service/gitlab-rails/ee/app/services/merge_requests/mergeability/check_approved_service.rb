# frozen_string_literal: true

module MergeRequests
  module Mergeability
    class CheckApprovedService < CheckBaseService
      CACHE_TTL = 60.seconds
      CACHE_KEY = 'merge_request:%{id}:approval_check'

      set_identifier :not_approved
      set_failure_explanation N_('The merge request must be approved.')
      set_description 'Checks whether the merge request is approved'

      def execute
        return inactive unless merge_request.approval_feature_available?
        return checking if merge_request.temporarily_unapproved?

        merge_request.approved? ? success : failure
      end

      def skip?
        params[:skip_approved_check].present?
      end

      def cacheable?
        # Only called when the results cache is used, so merges (use_cache: false) never memoize the lookup
        !merge_request.temporarily_unapproved?(memoize: true)
      end

      def cache_key
        format(CACHE_KEY, id: merge_request.id)
      end

      def cache_ttl
        CACHE_TTL
      end

      def invalidate
        Gitlab::MergeRequests::Mergeability::ResultsStore
          .new(merge_request: merge_request)
          .delete(merge_check: self)
      end
    end
  end
end
