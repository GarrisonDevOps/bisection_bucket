# frozen_string_literal: true

module Ai
  module Catalog
    module ItemConsumers
      # Given an `Ai::Catalog::Item` and a `Project` or `Group` container, resolves the
      # active service account for the matching `ItemConsumer`.
      class ResolveServiceAccountService
        include Gitlab::Utils::StrongMemoize

        def initialize(container:, item:)
          @container = container
          @item = item
        end

        def execute
          return error('No item consumer found for the root namespace.') unless item_consumer

          service_account = item_consumer.active_service_account
          return error('Could not find a valid service account for this agent/flow.') unless service_account

          ServiceResponse.success(payload: { service_account: service_account })
        end

        private

        attr_reader :container, :item

        def error(message)
          ServiceResponse.error(message: message)
        end

        def item_consumer
          consumer = item.consumers.for_projects(container).first if container.is_a?(::Project)
          consumer || item.consumers.for_groups(container.root_ancestor).first
        end
        strong_memoize_attr :item_consumer
      end
    end
  end
end
