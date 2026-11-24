# frozen_string_literal: true

module API
  class MergeRequestApprovals < ::API::Base
    before { authenticate_non_get! }

    feature_category :source_code_management

    helpers ::API::Helpers::MergeRequestsHelpers
    helpers ::Gitlab::NotesCreateRateLimit

    helpers do
      def present_approval(merge_request)
        present merge_request, with: ::API::Entities::MergeRequestApprovals, current_user: current_user
      end
    end

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
      requires :merge_request_iid, type: Integer, desc: 'Internal ID of the merge request.'
    end
    resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      segment ':id/merge_requests/:merge_request_iid' do
        # Get the status of the merge request's approvals
        #
        # Parameters:
        #   id (required)                 - The ID of a project
        #   merge_request_iid (required)  - IID of MR
        # Examples:
        #   GET /projects/:id/merge_requests/:merge_request_iid/approvals
        desc 'Retrieve approval state for a merge request' do
          detail 'Retrieves the approval state for a specified merge request. In the response, `approved_by` ' \
            'contains information about all approvers of the merge request, regardless of whether those approvals ' \
            'satisfy any approval rule. In GitLab Community Edition, the response contains only `approved`, ' \
            '`approved_by`, `user_can_approve`, and `user_has_approved`, and `approved` is `true` only when at ' \
            'least one approval exists. Otherwise, `approved` is `true` when the approval rules are satisfied, ' \
            'including when no approval rules apply and `approved_by` is empty.'
          success ::API::Entities::MergeRequestApprovals
          failure [
            { code: 404, message: 'Not found' }
          ]
          tags ['merge_request_approvals']
        end
        route_setting :authorization, permissions: :read_merge_request_approval_state, boundary_type: :project
        get 'approvals', urgency: :low do
          merge_request = find_merge_request_with_access(params[:merge_request_iid])

          present_approval(merge_request)
        end

        # Approve a merge request
        #
        # Parameters:
        #   id (required)                 - The ID of a project
        #   merge_request_iid (required)  - IID of MR
        # Examples:
        #   POST /projects/:id/merge_requests/:merge_request_iid/approve
        #
        desc 'Approve merge request' do
          detail 'Approves a specified merge request. The currently authenticated user must be an eligible approver. ' \
            'The `sha` parameter ensures you are approving the current version of the merge request. If defined, ' \
            'the value must match the merge request’s HEAD commit SHA. A mismatch returns a `409 Conflict` response. ' \
            'An approval sent immediately after the merge request is created can come before its commit is ' \
            'processed, and a new commit can then reset the approval. To avoid this, wait until ' \
            '`detailed_merge_status` is not `checking` or `approvals_syncing` and the merge request diff has a ' \
            '`patch_id_sha`, or send `sha`. With `sha`, GitLab records the approved version even before a diff ' \
            'exists, so a later push does not reset the approval. The response has the same attributes as ' \
            'retrieving the approval state, which depend on the edition.'
          success code: 201, model: ::API::Entities::MergeRequestApprovals
          failure [
            { code: 404, message: 'Not found' },
            { code: 401, message: 'Unauthorized' }
          ]
          tags ['merge_request_approvals']
        end
        params do
          optional :sha, type: String, desc: 'SHA at `HEAD` of the source branch of the merge request.'
          optional :publish_review, type: Boolean, desc: 'If `true`, submits pending review comments.'

          use :ee_approval_params
        end
        route_setting :authorization, permissions: :approve_merge_request, boundary_type: :project
        post 'approve', urgency: :low do
          merge_request = find_merge_request_with_access(params[:merge_request_iid], :approve_merge_request)

          check_sha_param!(params, merge_request)

          if params[:publish_review]
            check_notes_create_rate_limit!(cost: merge_request.draft_notes.authored_by(current_user).count)
          end

          # Started after the lookup and SHA check so 404s and 409s stay out of the SLI.
          experience = Labkit::UserExperienceSli.start(:approve_merge_request)
          outcome = :error

          if params[:publish_review]
            publish_result = ::DraftNotes::PublishService.new(merge_request, current_user).execute

            unless publish_result[:status] == :success
              outcome = :publish_review_failed
              experience.error!('Failed to publish review')
              render_api_error!('Failed to publish review', 500)
            end

            experience.checkpoint(checkpoint_action: 'notes_published')
          end

          result =
            ::MergeRequests::ApprovalService
              .new(project: user_project, current_user: current_user, params: params)
              .execute(merge_request)

          # A refused approve is a handled outcome, not an SLI error; the reason goes to the log.
          outcome = result.success? ? :success : (result.reason || :refused)

          unauthorized! unless result.success?

          present_approval(merge_request)
        rescue StandardError => e
          experience&.error!(e.message)
          raise
        ensure
          experience&.complete(approval_result: outcome)
        end

        desc 'Unapprove a merge request' do
          detail 'Unapproves a merge request. Removes the approval for the currently authenticated user from a ' \
            'specified merge request. The response has the same attributes as retrieving the approval state, which ' \
            'depend on the edition.'
          success code: 201, model: ::API::Entities::MergeRequestApprovals
          failure [
            { code: 404, message: 'Not found' },
            { code: 401, message: 'Unauthorized' }
          ]
          tags ['merge_request_approvals']
        end
        route_setting :authorization, permissions: :unapprove_merge_request, boundary_type: :project
        post 'unapprove', urgency: :low do
          merge_request = find_merge_request_with_access(params[:merge_request_iid], :approve_merge_request)

          success = ::MergeRequests::RemoveApprovalService
            .new(project: user_project, current_user: current_user)
            .execute(merge_request)

          not_found! unless success

          present_approval(merge_request)
        end

        desc 'Reset approvals for a merge request' do
          detail 'Resets all approvals for a specified merge request. Available only to bot users with a valid ' \
            'project or group token. Human users receive a `401 Unauthorized` response.'
          failure [
            { code: 401, message: 'Unauthorized' },
            { code: 404, message: 'Not found' }
          ]
          tags %w[merge_request_approvals]
        end
        route_setting :authorization, permissions: :reset_approvals_merge_request, boundary_type: :project
        put 'reset_approvals', urgency: :low do
          merge_request = find_project_merge_request(params[:merge_request_iid])

          unauthorized! unless Ability.allowed?(current_user, :reset_merge_request_approvals, merge_request) &&
            !merge_request.merged?

          merge_request.approvals.delete_all

          merge_request.delete_approval_mergeability_cache

          status :accepted
        end
      end
    end
  end
end

API::MergeRequestApprovals.prepend_mod_with('API::MergeRequestApprovals')
