# frozen_string_literal: true

module EE
  module MergeRequests
    module BaseService
      extend ::Gitlab::Utils::Override
      include ::Gitlab::InternalEventsTracking

      private

      attr_accessor :blocking_merge_requests_params, :duo_review_user, :requested_duo_code_review_depth,
        :automatic_security_reviewer

      def assign_duo_as_reviewer_automatically(merge_request)
        project = merge_request.project
        return unless project.auto_duo_code_review_enabled
        return unless ::Gitlab::Duo::CodeReview.automatic_review_available?(project)

        author = merge_request.author
        return unless author

        service = ::Gitlab::Duo::CodeReview::AutomatedRulesResolver.new(project, current_user)
        return if service.excluded?(merge_request)
        return unless duo_code_review_pipeline_permitted?(merge_request, author)

        if merge_request.ai_review_merge_request_allowed?(author)
          self.duo_review_user = author
          duo_bot = ::Users::Internal.in_organization(project.organization_id).duo_code_review_bot
          merge_request.reviewers << duo_bot unless merge_request.reviewer_ids.include?(duo_bot.id)
        else
          merge_request.duo_code_review_attempted = :automatic
        end
      end

      # Assigns the Security Review Flow to run as the author, like an automatic Duo Code Review,
      # so the author is billed whoever marks the merge request ready.
      def assign_security_review_as_reviewer_automatically(merge_request)
        automatic = ::Gitlab::Duo::SecurityReview::Automatic
        return unless automatic.applicable?(merge_request)

        service_account = automatic.trigger_for(merge_request.project)&.service_account
        return unless service_account
        return if merge_request.reviewer_ids.include?(service_account.id)
        return unless automatic.permitted?(merge_request, merge_request.author)

        self.automatic_security_reviewer = service_account
        merge_request.reviewers << service_account
      end

      def schedule_automatic_security_review(merge_request)
        ::Ai::FlowTriggers::AutomaticSecurityReviewWorker.perform_async(merge_request.id)
      end

      override :handle_reviewers_change
      def handle_reviewers_change(merge_request, old_reviewers)
        super
        new_reviewers = merge_request.reviewers - old_reviewers
        set_requested_changes(merge_request, new_reviewers) if new_reviewers.any?

        if new_reviewers.any?(&:duo_code_review_bot?)
          request_duo_code_review(merge_request, depth: requested_duo_code_review_depth)
        end

        flow_trigger_reviewers = new_reviewers
        # The automatic review bills the author, so it must not also run as the current user.
        if automatic_security_reviewer && new_reviewers.include?(automatic_security_reviewer)
          flow_trigger_reviewers -= [automatic_security_reviewer]
          # On create, AfterCreateService starts it once the diffs exist.
          schedule_automatic_security_review(merge_request) unless merge_request.previously_new_record?
        end

        execute_flow_triggers(merge_request, flow_trigger_reviewers, :assign_reviewer)
        trigger_merge_request_ai_suggested_reviewers_updated(merge_request)
        track_ai_suggested_reviewers_assigned(merge_request, new_reviewers)
      end

      # Assigning a reviewer drops that user from the suggestions, so subscribers
      # need the recalculated list even though no suggestion record changed.
      def trigger_merge_request_ai_suggested_reviewers_updated(merge_request)
        return unless ::Gitlab::Duo::RecommendReviewers.available?(merge_request.project)

        ::GraphqlTriggers.merge_request_ai_suggested_reviewers_updated(merge_request)
      end

      def track_ai_suggested_reviewers_assigned(merge_request, new_reviewers)
        return if new_reviewers.empty? || params[:auto_assigned]
        return unless ::Gitlab::Duo::RecommendReviewers.available?(merge_request.project)

        assigned_count = merge_request.ai_suggested_reviewers.for_users(new_reviewers.map(&:id)).count
        return if assigned_count == 0

        track_internal_event(
          'assign_duo_suggested_reviewer',
          project: merge_request.project,
          user: current_user,
          additional_properties: {
            property: merge_request.id.to_s,
            value: assigned_count
          }
        )
      end

      override :execute_external_hooks
      def execute_external_hooks(merge_request, merge_data)
        merge_request.project.execute_external_compliance_hooks(merge_data)
      end

      override :filter_params
      def filter_params(merge_request)
        unless Ability.allowed?(current_user, :update_approvers, merge_request)
          params.delete(:approvals_before_merge)
          params.delete(:approver_ids)
          params.delete(:approver_group_ids)
        end

        # Only users who have permission to merge can update this value
        params.delete(:override_requested_changes) unless merge_request.can_be_merged_by?(current_user)

        self.params = filter_approval_params(merge_request, current_user, params)

        self.blocking_merge_requests_params =
          ::MergeRequests::UpdateBlocksService.extract_params!(params)

        extract_duo_code_review_depth!(params)

        super
      end

      def extract_duo_code_review_depth!(params)
        depth = params.delete(:duo_code_review_depth)
        return unless depth && ::Gitlab::Duo::CodeReview.standard_available?(project: project)

        self.requested_duo_code_review_depth = depth
      end

      def filter_approval_params(merge_request, current_user, params)
        ApprovalRules::ParamsFilteringService.new(merge_request, current_user, params).execute
      end

      def set_requested_changes(merge_request, new_reviewers)
        requested_changes_users = merge_request.requested_changes_for_users(new_reviewers.map(&:id))

        merge_request.merge_request_reviewers_with(requested_changes_users.select(:user_id))
          .update_all_state(:requested_changes)
      end

      override :request_duo_code_review
      def request_duo_code_review(merge_request, depth: nil)
        # NOTE: Skip if the merge_request has just been created and its diffs are not yet ready since
        #   they are generated asynchronously.
        #   Duo code review will then be triggered in AfterCreateService after diffs are created.
        return unless merge_request.duo_code_review_startable?

        # Use the MR author for automatic flows (set by assign_duo_as_reviewer_automatically
        # or refresh_service). Falls back to current_user for manual reviewer additions.
        user = duo_review_user || current_user

        if use_duo_agent_platform?(merge_request, user: user)
          start_duo_code_review(merge_request, user, duo_code_review_parent_workflow, depth)
        elsif merge_request.ai_review_merge_request_allowed?(user)
          ::Llm::ReviewMergeRequestService.new(user, merge_request).execute
        end
      end

      # Out of band so a merge request created or un-drafted by another Duo flow can be
      # reviewed at all: a request carries only one composite identity.
      # See https://gitlab.com/gitlab-org/gitlab/-/work_items/612038.
      def start_duo_code_review(merge_request, user, parent_workflow, depth)
        if ::Feature.enabled?(:duo_code_review_clean_identity_start, merge_request.project)
          # The worker links no composite identity, so it cannot resolve a service account
          # back to the human holding the add-on seat. Resolve here instead.
          actor = duo_code_review_actor(user)
          return log_no_billable_actor(merge_request, user) unless actor

          # A parent needs the ai_flow_trigger_chaining flag, so jobs stay two-argument until it is enabled.
          # Only trailing nils are dropped, so a depth without a parent stays in the fourth slot.
          args = [merge_request.id, actor.id, parent_workflow&.id, depth]
          args.pop while args.last.nil?
          ::Ai::DuoWorkflows::CodeReview::StartReviewWorker.perform_async(*args)
        else
          ::Ai::DuoWorkflows::CodeReview::ReviewMergeRequestService.new(
            user: user,
            merge_request: merge_request,
            parent_workflow: parent_workflow,
            depth: depth
          ).execute
        end
      end

      # Only a request from the flow itself carries the workflow id, so reviews started later
      # from Sidekiq, such as automatic reviews on push, still start without a parent.
      # Automatic reviews run as the author, who may not own the flow's workflow.
      def duo_code_review_parent_workflow
        return if duo_review_user
        return unless flow_originated_chainable_request?

        ::Ai::FlowTriggers::CallerContext.authorized_parent_workflow_for_request(current_user)
      end

      # Resolves this user's own linked identity, not the request's. User#authorization_user
      # reads whichever identity the request carries, which on the automatic path is the
      # pusher's rather than the author's - billing a human who never requested the review.
      #
      # Nil for a composite service account with no identity of its own linked: the gate
      # above resolved entitlement through another flow's identity, so there is no human to
      # bill and the worker would find an account that can hold no add-on seat.
      #
      # `composite_ai_service_account?` and not `composite_identity_enforced?` alone: a composite request
      # arrives as the SCOPED USER carrying an in-memory override, and that user is already the
      # resolved human, so returning it unchanged is the answer rather than a fallback.
      def duo_code_review_actor(user)
        return user unless user.composite_ai_service_account?

        identity = ::Gitlab::Auth::Identity.fabricate(user)
        return unless identity.linked?

        identity.scoped_user
      end

      def log_no_billable_actor(merge_request, user)
        ::Gitlab::AppLogger.info(
          message: 'Duo Code Review flow not started: no billable human for the requesting identity',
          merge_request_id: merge_request.id,
          Labkit::Fields::GL_USER_ID => user.id
        )

        nil
      end

      def use_duo_agent_platform?(merge_request, user: current_user)
        strong_memoize_with(:use_duo_agent_platform, merge_request, user) do
          ::Gitlab::Duo::CodeReview.dap?(user: user, container: merge_request.project)
        end
      end

      def duo_code_review_pipeline_permitted?(merge_request, user)
        return true unless use_duo_agent_platform?(merge_request, user: user)

        clean_identity_start = ::Feature.enabled?(:duo_code_review_clean_identity_start, merge_request.project)
        actor = clean_identity_start ? duo_code_review_actor(user) : user
        return true unless actor
        return true if Ability.allowed?(actor, :create_duo_workflow_for_ci, merge_request.project)

        ::Gitlab::AppLogger.info(
          message: 'Automatic Duo Code Review skipped: author cannot create the flow pipeline',
          merge_request_id: merge_request.id,
          Labkit::Fields::GL_USER_ID => actor.id
        )

        false
      end

      def reset_approvals?(merge_request, _newrev)
        delete_approvals?(merge_request) ||
          merge_request.target_project.project_setting.selective_code_owner_removals ||
          selective_code_owner_removals_from_policy?(merge_request)
      end

      def delete_approvals?(merge_request)
        merge_request.target_project.reset_approvals_on_push ||
          merge_request.policy_approval_settings.fetch(:remove_approvals_with_new_commit, false)
      end

      def selective_code_owner_removals_from_policy?(merge_request)
        return false unless ::Feature.enabled?(
          :approval_policy_selective_code_owner_removals, merge_request.target_project)

        merge_request.policy_approval_settings.fetch(:remove_code_owner_approvals_with_new_commit, false)
      end

      def delete_approvals(merge_request, patch_id_sha: nil, cause: nil)
        approvals = merge_request.approvals
        approvals = filter_approvals(approvals, patch_id_sha) if patch_id_sha.present?
        approver_ids = approvals.map(&:user_id)

        # Only return early if there are no approvals at all, not just empty approver_ids
        return if approvals.empty?

        # Check if merge request is approved BEFORE deleting any approvals
        # We need to clear the approval state cache to get the current state
        merge_request.reset_approval_cache!
        was_approved = merge_request.approval_state.all_approval_rules_approved?

        approvals.delete_all

        # In case there is still a temporary flag on the MR
        merge_request.approval_state.expire_unapproved_key!

        merge_request.batch_update_reviewer_state(approver_ids, 'unapproved')

        trigger_merge_request_merge_status_updated(merge_request)
        trigger_merge_request_approval_state_updated(merge_request)
        publish_approvals_reset_event(merge_request, cause, approver_ids)

        # Trigger webhook events for system-initiated approval resets
        return unless cause == :new_push

        # Check approval state AFTER deletion to determine correct webhook event
        # Clear the approval state cache again to ensure we get the updated state after deletion
        merge_request.reset_approval_cache!
        is_currently_approved = merge_request.approval_state.all_approval_rules_approved?

        # Only send 'unapproved' if the MR transitioned from approved to not approved
        if was_approved && !is_currently_approved
          execute_hooks(merge_request, 'unapproved', system: true, system_action: 'approvals_reset_on_push')
        else
          # Send 'unapproval' for individual approval removal that doesn't change overall approval state
          execute_hooks(merge_request, 'unapproval', system: true, system_action: 'approvals_reset_on_push')
        end
      end

      def filter_approvals(approvals, patch_id_sha)
        approvals.with_invalid_patch_id_sha(patch_id_sha)
      end

      def all_approvers(merge_request)
        merge_request.overall_approvers(exclude_code_owners: true)
      end

      def publish_approvals_reset_event(merge_request, cause, approver_ids)
        return if cause.nil?
        return if approver_ids.empty?

        ::Gitlab::EventStore.publish(
          ::MergeRequests::ApprovalsResetEvent.new(
            data: {
              current_user_id: current_user.id,
              merge_request_id: merge_request.id,
              cause: cause.to_s,
              approver_ids: approver_ids
            }
          )
        )
      end

      def audit_security_policy_branch_bypass(merge_request)
        matching_policies = merge_request.security_policies_with_branch_exceptions

        return if matching_policies.empty?

        track_internal_event('check_merge_request_branch_exceptions_bypass', project: merge_request.project,
          additional_properties: {
            value: merge_request.id
          }
        )

        matching_policies.each do |policy|
          log_audit_event_for_policy_bypass(merge_request, policy)
        end
      end

      def log_audit_event_for_policy_bypass(merge_request, policy)
        project = merge_request.project
        message = <<~MSG.squish
          Approvals in merge request (#{project.full_path}!#{merge_request.iid}) with source branch
          '#{merge_request.source_branch}' and target branch '#{merge_request.target_branch}'
          was bypassed by security policy
        MSG

        ::Gitlab::Audit::Auditor.audit({
          name: 'merge_request_branch_bypassed_by_security_policy',
          author: current_user,
          scope: policy.security_policy_management_project,
          target: policy,
          message: message,
          additional_details: {
            merge_request_id: merge_request.id,
            merge_request_iid: merge_request.iid,
            source_branch: merge_request.source_branch,
            target_branch: merge_request.target_branch,
            project_id: project.id
          }
        })
      end

      def log_audit_event(merge_request, event_name, message)
        audit_context = {
          name: event_name,
          author: current_user,
          scope: merge_request.target_project,
          target: merge_request,
          message: message,
          target_details:
            { iid: merge_request.iid,
              id: merge_request.id,
              source_branch: merge_request.source_branch,
              target_branch: merge_request.target_branch }
        }

        if event_name == 'merge_request_merged_by_project_bot'
          audit_context[:target_details][:merge_commit_sha] = merge_request.merge_commit_sha
        end

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def merge_requests_for_approval_reset(branch_name)
        scope = project.source_of_merge_requests
          .by_source_branch(branch_name)
          .with_state(:opened)
          .with_existing_approval

        scope.preload(:source_project).select(&:source_project) # rubocop:disable CodeReuse/ActiveRecord -- already exists in this class
      end
    end
  end
end
