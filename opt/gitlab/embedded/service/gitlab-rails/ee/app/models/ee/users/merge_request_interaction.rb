# frozen_string_literal: true

module EE
  module Users
    module MergeRequestInteraction
      extend ::Gitlab::Utils::Override

      override :can_update?
      def can_update?
        if current_user && user.duo_code_review_bot?
          return merge_request.project.ai_review_merge_request_allowed?(current_user)
        end

        super
      end

      def applicable_approval_rules
        return [] unless merge_request.project.licensed_feature_available?(:merge_request_approvers)

        merge_request.applicable_approval_rules_for_user(user.id)
      end
    end
  end
end
