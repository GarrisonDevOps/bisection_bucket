# frozen_string_literal: true

module EE
  module API
    module Entities
      module MergeRequestApprovals
        extend ActiveSupport::Concern

        prepended do
          # Enterprise Edition answers the merge request approval endpoints with
          # the approval state of the merge request. Exposing it here, rather than
          # presenting another entity from the endpoints, keeps the entity their
          # `desc` blocks declare the one that renders the response, so the
          # generated OpenAPI documents describe what these endpoints return.
          unexpose_all

          expose :approval_state, merge: true, using: ::API::Entities::ApprovalState
        end
      end
    end
  end
end
