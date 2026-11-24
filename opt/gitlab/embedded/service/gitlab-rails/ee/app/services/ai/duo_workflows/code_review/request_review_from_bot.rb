# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CodeReview
      # A re-review request needs RequestReviewService; a first review needs
      # the bot added as reviewer. Returns the raw result of whichever ran.
      class RequestReviewFromBot
        def initialize(merge_request:, current_user:, bot:)
          @merge_request = merge_request
          @current_user = current_user
          @bot = bot
        end

        def execute
          if merge_request.reviewer_ids.include?(bot.id)
            ::MergeRequests::RequestReviewService.new(
              project: merge_request.project,
              current_user: current_user
            ).execute(merge_request, bot)
          else
            ::MergeRequests::UpdateReviewersService.new(
              project: merge_request.project,
              current_user: current_user,
              params: { reviewer_ids: merge_request.reviewer_ids | [bot.id] }
            ).execute(merge_request)
          end
        end

        private

        attr_reader :merge_request, :current_user, :bot
      end
    end
  end
end
