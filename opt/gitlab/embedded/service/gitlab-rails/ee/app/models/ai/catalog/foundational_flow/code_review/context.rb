# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module CodeReview
        module Context
          module_function

          # Code Review posts its comments as this bot, not as the flow's service
          # account, so the flow cannot use service_account_name to recognise them.
          def call(runtime_context:)
            resource = runtime_context.resource
            return {} unless resource.is_a?(::MergeRequest)

            review_bot = ::Users::Internal
              .in_organization(resource.project.organization_id)
              .duo_code_review_bot

            {
              "duo_code_review_bot_name" => review_bot.username,
              "last_reviewed_head_sha" => resource.duo_code_review_last_reviewed_head_sha(review_bot)
            }.compact
          end
        end
      end
    end
  end
end
