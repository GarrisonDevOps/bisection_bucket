# frozen_string_literal: true

module MergeRequests
  class CreateBlockService
    include ::Gitlab::Allowable

    def initialize(user:, merge_request:, blocking_merge_request_id:)
      @user = user
      @merge_request = merge_request
      @blocking_merge_request_id = blocking_merge_request_id
    end

    def execute
      unless can?(user, :update_merge_request, merge_request)
        return ::ServiceResponse.error(message: _("Lacking permissions to update the merge request"),
          reason: :forbidden)
      end

      blocking_mr = ::MergeRequest.find_by_id(blocking_merge_request_id)

      if blocking_mr.nil?
        return ::ServiceResponse.error(message: _("Blocking merge request not found"), reason: :not_found)
      end

      unless can?(user, :read_merge_request, blocking_mr)
        return ::ServiceResponse.error(message: _("Lacking permissions to the blocking merge request"),
          reason: :forbidden)
      end

      block = ::MergeRequestBlock.create(
        blocking_merge_request_id: blocking_mr.id,
        blocked_merge_request_id: merge_request.id
      )

      block_exists = block.errors.any? { |error| error.try(:type) == :taken }

      return ::ServiceResponse.error(message: _("Block already exists"), reason: :conflict) if block_exists

      unless block.persisted?
        return ::ServiceResponse.error(message: block.errors.full_messages.join(', '), reason: :bad_request)
      end

      create_notes(block)

      ::ServiceResponse.success(payload: { merge_request_block: block })
    end

    private

    def create_notes(block)
      SystemNoteService.block_issuable(block.blocking_merge_request, block.blocked_merge_request, user)
      SystemNoteService.blocked_by_issuable(block.blocked_merge_request, block.blocking_merge_request, user)
    end

    attr_reader :merge_request, :blocking_merge_request_id, :user
  end
end
