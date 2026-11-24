# frozen_string_literal: true

module Types
  module PermissionTypes
    module Ai
      module Catalog
        class ItemConsumer < BasePermissionType
          graphql_name 'AiCatalogItemConsumerPermissions'
          description 'Check permissions for the current user on an AI catalog item consumer.'

          authorize_granular_token skip_reason: :parent_authorizes

          abilities :read_ai_catalog_item_consumer, :admin_ai_catalog_item_consumer, :execute_ai_catalog_item
        end
      end
    end
  end
end
