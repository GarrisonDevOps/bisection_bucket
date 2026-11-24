# frozen_string_literal: true

module MergeRequests
  class DestroyBlockService
    include ::Gitlab::Allowable

    def initialize(user:, block:)
      @user = user
      @block = block
    end

    def execute
      unless can?(user, :update_merge_request, block.blocked_merge_request)
        return ::ServiceResponse.error(message: _("Lacking permissions to update the merge request"),
          reason: :forbidden)
      end

      block.destroy!
      create_notes

      ::ServiceResponse.success(message: 'Relation was removed')
    end

    private

    def create_notes
      SystemNoteService.unrelate_issuable(block.blocking_merge_request, block.blocked_merge_request, user)
      SystemNoteService.unrelate_issuable(block.blocked_merge_request, block.blocking_merge_request, user)
    end

    attr_reader :block, :user
  end
end
