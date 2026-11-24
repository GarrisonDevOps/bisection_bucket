# frozen_string_literal: true

module EE
  module MergeRequests
    module MergeService
      extend ::Gitlab::Utils::Override

      def skipping_active_merge_train?
        params[:skip_merge_train] && project.merge_trains_skip_train_allowed?
      end

      private

      # Re-checks approval inside in_locked_state (after the MR is locked) to close
      # the unapprove-during-merge race. https://gitlab.com/gitlab-org/gitlab/-/issues/604469
      override :commit
      def commit
        ensure_approved!

        # Create the skip_merged car BEFORE the git push so sha_exists_in_history?
        # covers the race window. https://gitlab.com/gitlab-org/gitlab/-/issues/741014
        if skipping_active_merge_train?
          skip_merged_car = MergeTrains::Car.insert_skip_merged_car_for(merge_request, current_user)
        end

        super
      rescue ::MergeRequests::MergeBaseService::MergeError, ::MergeRequests::MergeStrategies::StrategyError
        # Both are raised only before anything lands on the target branch;
        # post-push failures keep the car since the commit is already on the branch.
        skip_merged_car&.destroy
        raise
      end

      def ensure_approved!
        return unless merge_request.approval_feature_available?

        merge_request.reset_approval_cache!

        raise_error('Merge request is not approved') unless merge_request.approved?
      end
    end
  end
end
