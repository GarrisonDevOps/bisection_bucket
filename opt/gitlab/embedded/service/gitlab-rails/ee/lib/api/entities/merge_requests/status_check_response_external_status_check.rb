# frozen_string_literal: true

module API
  module Entities
    module MergeRequests
      # Renders the external status check returned by POST status_check_responses.
      #
      # Mirrors the read path (GET status_checks -> Entities::MergeRequests::StatusCheck)
      # rather than Entities::ExternalStatusCheck: it exposes only id/name and the
      # query-string-stripped, permission-gated external_url. This keeps Developer-level
      # callers of the status check responses endpoint from reading query-string secrets
      # in external_url, and from seeing the project_id/protected_branches/hmac
      # configuration the read path never exposed.
      class StatusCheckResponseExternalStatusCheck < Grape::Entity
        expose :id, documentation: { type: 'Integer', example: 1 }
        expose :name, documentation: { type: 'String', example: 'QA' }
        expose :external_url, documentation: { type: 'String', example: 'https://www.example.com' }

        def external_url
          if Ability.allowed?(options[:current_user], :read_merge_request_status_check_url, object.project)
            return object.external_url&.[](/[^?]+/)
          end

          ''
        end
      end
    end
  end
end
