# frozen_string_literal: true

module Mutations
  module Ai
    module Catalog
      class ItemReport < BaseMutation
        graphql_name 'AiCatalogItemReport'

        argument :id, ::Types::GlobalIDType[::Ai::Catalog::Item],
          required: true,
          description: 'Global ID of the catalog item to report.'

        argument :reason, ::Types::Ai::Catalog::ItemReportReasonEnum,
          required: true,
          description: 'Reason for reporting the catalog item.'

        argument :body, GraphQL::Types::String,
          required: false,
          description: 'Additional details about the report. Limited to 1000 characters.',
          validates: { length: { maximum: 1000 } }

        authorize :report_ai_catalog_item
        authorize_granular_token permissions: :report_ai_catalog_item,
          boundary_argument: :id, boundary: :project, boundary_type: :project

        def resolve(id:, reason:, body: nil)
          item = authorized_find!(id: id)

          if Gitlab::ApplicationRateLimiter.throttled?(:ai_catalog_item_report, scope: { user: current_user })
            return {
              errors: ['You have reported this item too many times. Please try again later.']
            }
          end

          if reason == 'other' && body.blank?
            return {
              errors: ['Additional details are required when reason is OTHER']
            }
          end

          ::Ai::CatalogItemAbuseReportMailer.notify(
            current_user.id, { item_id: item.id, reason: reason, message: body }
          ).deliver_later

          {
            errors: []
          }
        end
      end
    end
  end
end
