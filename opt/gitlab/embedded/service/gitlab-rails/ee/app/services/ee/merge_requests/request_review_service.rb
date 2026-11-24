# frozen_string_literal: true

module EE
  module MergeRequests
    module RequestReviewService
      extend ::Gitlab::Utils::Override

      override :with_valid_reviewer
      def with_valid_reviewer(merge_request, user)
        if user.duo_code_review_bot? &&
            !use_duo_agent_platform?(merge_request) &&
            !merge_request.ai_review_merge_request_allowed?(current_user)
          return error(::Gitlab::Duo::CodeReview::Messages.manual_error)
        end

        super
      end

      override :request_duo_code_review
      def request_duo_code_review(merge_request)
        super(merge_request, depth: duo_code_review_depth)
      end

      private

      def duo_code_review_depth
        depth = params[:duo_code_review_depth]
        return unless depth && ::Gitlab::Duo::CodeReview.standard_available?(project: project)

        depth
      end
    end
  end
end
