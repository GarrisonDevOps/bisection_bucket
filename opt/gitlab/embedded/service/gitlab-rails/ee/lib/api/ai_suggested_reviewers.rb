# frozen_string_literal: true

module API
  class AiSuggestedReviewers < ::API::Base
    include APIGuard
    include ::API::Concerns::AiWorkflowsAccess

    feature_category :code_review_workflow

    MAX_SUGGESTIONS = 50
    REASON_LIMIT = ::MergeRequests::AiSuggestedReviewer::REASON_LIMIT
    RECOMMEND_REVIEWERS_FLOW = 'recommend_reviewers/v1'

    before { authenticate! }

    allow_ai_workflows_access

    helpers ::API::Helpers::MergeRequestsHelpers
    helpers ::API::Helpers::DuoWorkflowHelpers

    helpers do
      def ai_suggested_reviewers_available!(merge_request)
        not_found! unless ::Gitlab::Duo::RecommendReviewers.available?(merge_request.project)
      end

      def unassigned_suggested_reviewers(merge_request)
        merge_request.ai_suggested_reviewers
          .excluding_reviewers(merge_request.reviewer_ids)
          .preload_user_and_approval_rules
          .order_id_asc
      end
    end

    params do
      requires :id, types: [String, Integer], desc: 'The ID or URL-encoded path of the project.'
      requires :merge_request_iid, type: Integer, desc: 'The internal ID of the merge request.'
    end
    resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      segment ':id/merge_requests/:merge_request_iid' do
        desc 'Set the AI-recommended reviewers for a merge request' do
          detail 'Replaces the AI-recommended reviewers persisted for a specified merge request. ' \
            'Available only when the recommend reviewers flow is enabled for the project.'
          success ::API::Entities::AiSuggestedReviewer
          is_array true
          failure [
            { code: 400, message: 'Bad request' },
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 429, message: 'Too many requests' }
          ]
          tags %w[gitlab_duo_workflows internal_operations]
        end
        params do
          requires :suggestions, type: Array, limit: MAX_SUGGESTIONS,
            desc: "Recommended reviewers (maximum is #{MAX_SUGGESTIONS})." do
            requires :user_id, type: Integer, desc: 'ID of the recommended user.'
            optional :reason, type: String, limit: REASON_LIMIT,
              desc: "Model rationale for the recommendation (maximum #{REASON_LIMIT} characters)."
            optional :approval_rule_id, type: Integer,
              desc: 'ID of the approval rule the user was suggested for.'
            given approval_rule_id: ->(value) { value.present? } do
              requires :approval_rule_type, type: String, values: %w[merge_request_rule project_rule],
                desc: 'Type of the approval rule the user was suggested for.'
            end
          end
        end
        route_setting :lifecycle, :experiment
        route_setting :authorization, skip_granular_token_authorization: :ai_workflows_oauth_auth
        post 'suggested_reviewers', urgency: :low do
          merge_request = find_merge_request_with_access(params[:merge_request_iid])

          verify_flow_composite_identity!(::Ai::Catalog::FoundationalFlow[RECOMMEND_REVIEWERS_FLOW], user_project)

          ai_suggested_reviewers_available!(merge_request)

          authorize!(:update_merge_request, merge_request)

          check_rate_limit!(:ai_suggested_reviewers_create, scope: { user: current_user, project: user_project })

          suggestions = params[:suggestions]

          result = ::MergeRequests::SaveAiSuggestedReviewersService.new(
            merge_request: merge_request,
            suggestions: suggestions
          ).execute

          if result.success?
            present unassigned_suggested_reviewers(merge_request),
              with: ::API::Entities::AiSuggestedReviewer
          else
            render_api_error!(result.message.to_sentence, 400)
          end
        end
      end
    end
  end
end
