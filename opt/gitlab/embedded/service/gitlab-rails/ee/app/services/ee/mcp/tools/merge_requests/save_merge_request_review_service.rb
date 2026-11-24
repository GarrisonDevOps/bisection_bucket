# frozen_string_literal: true

module EE
  module Mcp
    module Tools
      module MergeRequests
        module SaveMergeRequestReviewService
          extend ::Gitlab::Utils::Override

          override :perform_post_duo_review
          def perform_post_duo_review(arguments)
            merge_request = resolve_merge_request!(arguments)
            authorize_merge_request_token!(merge_request, :update_merge_request)

            unless merge_request.ai_review_merge_request_allowed?(current_user)
              return ::Mcp::Tools::Base::Response.error(
                'GitLab Duo Code Review is not available for this merge request. It requires GitLab Duo ' \
                  'to be enabled for the project and permission to create notes.',
                reason: ::Mcp::Tools::Base::Response::Reason::UNAUTHORIZED
              )
            end

            if review_in_progress?(merge_request)
              return method_response(merge_request, 'post_duo_review',
                'already_in_progress')
            end

            error_response = request_review_from_duo_bot(merge_request)
            return error_response if error_response

            method_response(merge_request, 'post_duo_review', 'review_requested')
          end

          private

          def review_in_progress?(merge_request)
            merge_request.duo_code_review_progress_note.present?
          end

          # Shared with CodeReviewHandler via RequestReviewFromBot.
          def request_review_from_duo_bot(merge_request)
            bot = duo_code_review_bot(merge_request)
            re_review = merge_request.reviewer_ids.include?(bot.id)

            result = ::Ai::DuoWorkflows::CodeReview::RequestReviewFromBot.new(
              merge_request: merge_request,
              current_user: current_user,
              bot: bot
            ).execute

            if re_review
              if result[:status] == :error
                return review_request_error(result[:message], failure_reason(:update_merge_request, merge_request))
              end
            elsif merge_request.reset.reviewer_ids.exclude?(bot.id)
              return review_request_error('the Duo bot could not be assigned as reviewer.',
                failure_reason(:set_merge_request_metadata, merge_request))
            end

            nil
          end

          def failure_reason(ability, merge_request)
            if Ability.allowed?(current_user, ability, merge_request)
              ::Mcp::Tools::Base::Response::Reason::ERROR
            else
              ::Mcp::Tools::Base::Response::Reason::UNAUTHORIZED
            end
          end

          def review_request_error(detail, reason)
            ::Mcp::Tools::Base::Response.error("Failed to request Duo Code Review: #{detail}", reason: reason)
          end

          def duo_code_review_bot(merge_request)
            ::Users::Internal.in_organization(merge_request.project.organization_id).duo_code_review_bot
          end
        end
      end
    end
  end
end
