# frozen_string_literal: true

module API
  module Entities
    module MergeRequests
      class StatusCheckResponse < Grape::Entity
        expose :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
        expose :merge_request, using: ::API::Entities::MergeRequest
        expose :external_status_check, using: ::API::Entities::MergeRequests::StatusCheckResponseExternalStatusCheck
      end
    end
  end
end
