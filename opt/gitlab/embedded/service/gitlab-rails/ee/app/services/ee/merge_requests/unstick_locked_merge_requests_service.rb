# frozen_string_literal: true

module EE
  module MergeRequests
    module UnstickLockedMergeRequestsService
      extend ::Gitlab::Utils::Override

      private

      override :should_unstick?
      def should_unstick?(merge_request)
        # We don't want this worker to process stuck MRs that are in merge train
        # as that will be in a separate issue: https://gitlab.com/gitlab-org/gitlab/-/issues/389044
        !merge_request.merge_train_car.present? && super
      end

      # rubocop: disable CodeReuse/ActiveRecord -- We only preload merge_train_car here
      override :merge_requests_batch
      def merge_requests_batch(ids)
        super.preload(:merge_train_car)
      end
      # rubocop: enable CodeReuse/ActiveRecord
    end
  end
end
