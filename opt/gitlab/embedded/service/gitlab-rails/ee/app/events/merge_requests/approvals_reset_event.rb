# frozen_string_literal: true

module MergeRequests
  class ApprovalsResetEvent < Gitlab::EventStore::Event
    def schema
      {
        'type' => 'object',
        'required' => %w[
          current_user_id
          merge_request_id
          cause
          approver_ids
        ],
        'properties' => {
          'current_user_id' => { 'type' => 'integer' },
          'merge_request_id' => { 'type' => 'integer' },
          'cause' => { 'type' => 'string' },
          'approver_ids' => { 'type' => 'array' }
        }
      }
    end
  end
end
