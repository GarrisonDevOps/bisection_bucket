# frozen_string_literal: true

module Ai
  module Catalog
    module Preloaders
      class ItemConsumerPolicyPreloader
        def initialize(consumers)
          @consumers = consumers
        end

        def execute
          preload_associations
          preload_root_ancestors
        end

        private

        attr_reader :consumers

        def preload_associations
          ActiveRecord::Associations::Preloader.new(
            records: consumers,
            associations: [
              { project: :namespace },
              :group,
              { item: [:organization, { project: :namespace }] }
            ]
          ).call
        end

        def preload_root_ancestors
          ::Namespaces::Preloaders::NamespaceRootAncestorPreloader.new(namespaces, [:namespace_settings]).execute
        end

        def namespaces
          @namespaces ||= consumers.flat_map do |consumer|
            [consumer.project&.namespace || consumer.group, consumer.item.project&.namespace]
          end.compact
        end
      end
    end
  end
end
