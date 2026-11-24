# frozen_string_literal: true

module EE
  module Mutations
    module MergeRequests
      module Accept
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        MERGE_TRAIN_ENFORCED = 'This project requires merge requests to go through the merge train. ' \
          'Set the merge strategy to add this merge request to the train.'

        # Reject a direct (immediate) merge when merge train enforcement is enabled for the project.
        # Only merges that go through a merge train strategy are allowed.
        override :validate
        def validate(merge_request, merge_service, merge_params)
          if merge_request.target_project.merge_train_enforced_for?(current_user) &&
              ::AutoMergeService::MERGE_TRAIN_STRATEGIES.exclude?(merge_params[:auto_merge_strategy])
            return MERGE_TRAIN_ENFORCED
          end

          super
        end
      end
    end
  end
end
