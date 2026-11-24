# frozen_string_literal: true

module MergeTrains
  class CreateRefService
    def initialize(current_user:, merge_request:, first_parent_ref:, source_sha: nil)
      @current_user = current_user
      @merge_request = merge_request
      @source_sha = source_sha
      @first_parent_ref = first_parent_ref
    end

    def execute
      create_ref_result = MergeRequests::CreateRefService.new(
        current_user: @current_user,
        merge_request: @merge_request,
        source_sha: @source_sha,
        target_ref: @merge_request.train_ref_path,
        first_parent_ref: @first_parent_ref
      ).execute

      return create_ref_result if create_ref_result.error?

      return create_ref_result if update_merge_params_train_ref(create_ref_result)

      ServiceResponse.error(message: "Failed to update merge params")
    end

    private

    def update_merge_params_train_ref(create_ref_result)
      params = {
        'train_ref' => create_ref_result
          .payload
          .slice(:commit_sha, :merge_commit_sha, :squash_commit_sha)
          .stringify_keys
      }
      @merge_request.append_merge_params(params)
      @merge_request.save
    end
  end
end
