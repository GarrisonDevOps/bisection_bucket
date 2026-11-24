# frozen_string_literal: true

Gitlab::Seeder.quiet do
  merge_request = MergeRequest.opened.first
  next warn "\nSkipping ai_suggested_reviewers seeds: no open merge request available" unless merge_request

  reviewer = User.human.where.not(id: merge_request.author_id).first
  next warn "\nSkipping ai_suggested_reviewers seeds: no reviewer available" unless reviewer

  MergeRequests::SaveAiSuggestedReviewersService.new(
    merge_request: merge_request,
    suggestions: [{ user_id: reviewer.id, reason: 'Recently reviewed similar changes.' }]
  ).execute

  print '.'
end
