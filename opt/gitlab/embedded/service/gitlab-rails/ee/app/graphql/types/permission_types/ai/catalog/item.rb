# frozen_string_literal: true

module Types
  module PermissionTypes
    module Ai
      module Catalog
        class Item < BasePermissionType
          graphql_name 'AiCatalogItemPermissions'
          description 'Check permissions for the current user on an AI catalog item.'

          authorize_granular_token parent_authorizes: :read_ai_catalog_item

          abilities :read_ai_catalog_item, :admin_ai_catalog_item, :report_ai_catalog_item,
            :force_hard_delete_ai_catalog_item

          def read_ai_catalog_item
            lazy_ability(:read_ai_catalog_item)
          end

          def admin_ai_catalog_item
            lazy_ability(:admin_ai_catalog_item)
          end

          def report_ai_catalog_item
            lazy_ability(:report_ai_catalog_item)
          end

          def force_hard_delete_ai_catalog_item
            Ability.allowed?(context[:current_user], :force_hard_delete_ai_catalog_item)
          end

          private

          def lazy_ability(ability)
            loader = ::Gitlab::Graphql::Loaders::Ai::Catalog::ItemWithProjectLoader.new(object, context[:current_user])

            Gitlab::Graphql::Lazy.with_value(loader.find) do |item|
              Ability.allowed?(context[:current_user], ability, item)
            end
          end
        end
      end
    end
  end
end
