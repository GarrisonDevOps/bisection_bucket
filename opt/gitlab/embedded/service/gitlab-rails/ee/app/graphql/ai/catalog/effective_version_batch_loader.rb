# frozen_string_literal: true

module Ai
  module Catalog
    class EffectiveVersionBatchLoader
      class << self
        def load_for(item, lazy_consumer, current_user)
          BatchLoader::GraphQL.for([item, lazy_consumer]).batch do |keys, loader|
            resolve_effective_versions(keys, loader, current_user)
          end
        end

        def resolve_effective_versions(keys, loader, current_user)
          preload_consumer_associations(keys)

          prefixes = keys.to_h do |key|
            _item, lazy_consumer = key
            [key, readable_pinned_version_prefix(lazy_consumer.sync, current_user)]
          end

          pinned_versions = pinned_versions_for(prefixes)
          latest_versions = latest_versions_for(keys, prefixes)

          keys.each do |key|
            item, _lazy_consumer = key
            prefix = prefixes[key]
            version = prefix ? pinned_versions[[item.id, prefix]] : latest_versions[item.latest_version_id]

            loader.call(key, version&.tap { |v| v.item = item })
          end
        end

        private

        def pinned_versions_for(prefixes)
          pairs = prefixes.filter_map { |(item, _lazy), prefix| [item.id, prefix] if prefix }
          return {} if pairs.empty?

          ::Ai::Catalog::ItemVersion.for_item_version_pairs(pairs).index_by do |version|
            [version.ai_catalog_item_id, version.version]
          end
        end

        def latest_versions_for(keys, prefixes)
          version_ids = keys.filter_map { |key| key.first.latest_version_id unless prefixes[key] }
          return {} if version_ids.empty?

          ::Ai::Catalog::ItemVersion.id_in(version_ids).index_by(&:id)
        end

        # The policy reads `consumer.item` and `consumer.container`. Reuse the items already in memory and
        # share one container instance across consumers, so its namespace and settings load once.
        def preload_consumer_associations(keys)
          consumers = keys.filter_map { |_item, lazy_consumer| lazy_consumer.sync }

          ActiveRecord::Associations::Preloader.new(
            records: consumers, associations: [:item, :project, :group], available_records: keys.map(&:first)
          ).call
        end

        def readable_pinned_version_prefix(consumer, current_user)
          return unless consumer
          return unless Ability.allowed?(current_user, :read_ai_catalog_item_consumer, consumer)

          consumer.pinned_version_prefix
        end
      end
    end
  end
end
