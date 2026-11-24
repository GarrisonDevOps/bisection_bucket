# frozen_string_literal: true

module MergeRequests
  class RequestedChange < ApplicationRecord
    self.table_name = 'merge_request_requested_changes'

    belongs_to :project
    belongs_to :merge_request
    belongs_to :user
  end
end
