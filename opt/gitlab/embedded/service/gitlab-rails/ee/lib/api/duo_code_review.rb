# frozen_string_literal: true

module API
  class DuoCodeReview < ::API::Base
    include APIGuard

    feature_category :dap_code_review

    allow_access_with_scope :ai_features

    before do
      not_found! unless Gitlab.dev_or_test_env?

      authenticate!

      license_feature_available = ::License.feature_available?(:review_merge_request)
      global_feature_flag_enabled = Gitlab::Llm::Utils::FlagChecker.flag_enabled_for_feature?(:review_merge_request)

      not_found! unless license_feature_available && global_feature_flag_enabled
    end

    namespace 'duo_code_review' do
      resources :evaluations do
        desc 'Evaluate code review' do
          detail 'Evaluates code changes using GitLab Duo code review'
          tags ['gitlab_duo']
        end
        params do
          requires :diffs, type: String,
            desc: 'Raw diffs to review.'
          requires :mr_title, type: String,
            desc: 'Title of the merge request.'
          requires :mr_description, type: String,
            desc: 'Description of the merge request.'
          requires :files_content, type: Hash,
            desc: 'Full file contents, where keys are file paths and values are the file contents.'
        end

        route_setting :authorization, skip_granular_token_authorization: :internal_testing
        post do
          evaluation_response = Gitlab::Llm::Evaluators::ReviewMergeRequest.new(
            user: current_user,
            tracking_context: {
              request_id: SecureRandom.uuid,
              action: 'review_merge_request'
            },
            options: declared_params
          ).execute

          # Find the last occurrence of <review>...</review> in the response
          # This ensures we get the actual review output, not any examples in thinking steps
          review_matches = evaluation_response.scan(%r{<review>.*?</review>}m)
          review_content = review_matches.last || evaluation_response

          review_response = { review: review_content }
          present review_response, with: Grape::Presenters::Presenter
        end
      end
    end
  end
end
