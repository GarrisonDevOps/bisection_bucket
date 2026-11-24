# frozen_string_literal: true

module EE
  module MergeRequests
    module RefreshService
      extend ::Gitlab::Utils::Override

      private

      override :refresh_merge_requests!
      def refresh_merge_requests!
        check_merge_train_status

        super

        remove_requested_changes
        request_duo_code_reviews
      end

      override :execute_async_workers
      def execute_async_workers
        super

        ::MergeRequests::Refresh::ApprovalWorker.perform_async(
          project.id,
          current_user.id,
          push.oldrev,
          push.newrev,
          push.ref
        )

        schedule_dap_factory_validations
      end

      # Checked per merge request, because a fork's merge requests target another project.
      def schedule_dap_factory_validations
        merge_requests = merge_requests_for_source_branch.select do |merge_request|
          ::Gitlab::Ai::SoftwareFactory.enabled?(merge_request.target_project)
        end
        return if merge_requests.empty?

        ::Ai::DapFactory::ValidateMergeRequestWorker.bulk_perform_async_with_contexts(
          merge_requests,
          arguments_proc: ->(merge_request) { [merge_request.id] },
          context_proc: ->(merge_request) { { project: merge_request.target_project } }
        )
      end

      override :abort_auto_merges?
      def abort_auto_merges?(merge_request)
        return true if merge_request.merge_train_car

        super
      end

      # rubocop:disable Gitlab/ModuleWithInstanceVariables
      def check_merge_train_status
        return unless @push.branch_updated?

        MergeTrains::CheckStatusService.new(project, current_user)
          .execute(project, @push.branch_name, @push.newrev)
      end

      def merge_requests_for_target_branch(reload: false, mr_states: [:opened])
        @target_merge_requests = nil if reload
        @target_merge_requests ||= project.merge_requests
          .with_state(mr_states)
          .by_target_branch(push.branch_name)
          .including_merge_train
      end
      # rubocop:enable Gitlab/ModuleWithInstanceVariables

      def remove_requested_changes
        return unless project.feature_available?(:requested_changes_block_merge_request)

        update_reviewer_service = ::MergeRequests::UpdateReviewerStateService
          .new(project: project, current_user: current_user)

        merge_requests_for_source_branch
          .select(&:merge_requests_disable_committers_approval?)
          .each do |merge_request|
            merge_request.destroy_requested_changes(current_user)
            update_reviewer_service.execute(merge_request, 'unreviewed')
          end
      end

      override :schedule_duo_code_review
      def schedule_duo_code_review(merge_request)
        return unless merge_request.project.auto_duo_code_review_enabled
        return if merge_request.draft?
        return unless merge_request.reviewers.duo_code_review_bot.any?

        # Attribute review to the MR author in this automatic flow. The git pusher
        # (current_user) may be a CI bot or another contributor unrelated to billing.
        # Reuse current_user object when they are the author to avoid an extra DB load.
        review_user = current_user.id == merge_request.author_id ? current_user : merge_request.author

        if review_on_push_enabled?(merge_request, review_user)
          return unless diff_changed?(merge_request)
        else
          previous_diff = merge_request.previous_diff
          return unless previous_diff && previous_diff.empty?
        end

        return unless duo_code_review_pipeline_permitted?(merge_request, review_user)

        duo_code_review_requests << [merge_request, review_user]
      end

      def duo_code_review_requests
        @duo_code_review_requests ||= []
      end

      def request_duo_code_reviews
        duo_code_review_requests.each do |merge_request, review_user|
          if review_on_push_enabled?(merge_request, review_user)
            ::Ai::DuoWorkflows::CodeReview::CancelReviewService.new(
              merge_request: merge_request,
              current_user: current_user
            ).execute
          end

          self.duo_review_user = review_user
          request_duo_code_review(merge_request)
        end
      end

      def review_on_push_enabled?(merge_request, review_user)
        merge_request.project.auto_duo_code_review_on_push_enabled &&
          use_duo_agent_platform?(merge_request, user: review_user)
      end

      def diff_changed?(merge_request)
        previous_patch_id = merge_request.previous_diff&.patch_id_sha
        current_patch_id = merge_request.merge_request_diff.patch_id_sha

        return true unless previous_patch_id && current_patch_id

        previous_patch_id != current_patch_id
      end
    end
  end
end
