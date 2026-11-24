# frozen_string_literal: true

module VirtualRegistries
  class Registry < ApplicationRecord
    self.abstract_class = true

    belongs_to :group

    validates :group, top_level_group: true, presence: true
    validates :name, presence: true, length: { maximum: 255 }
    validates :description, length: { maximum: 1024 }
    validates :name, uniqueness: { scope: :group_id }
    validate :max_per_group, on: :create

    scope :for_group, ->(group) { where(group: group) }

    before_destroy :delete_upstreams

    def self.declarative_policy_class
      'VirtualRegistries::Policies::GroupPolicy'
    end

    def exclusive_upstreams
      registry_upstreams_klass = self.class.module_parent::RegistryUpstream
      upstream_klass = self.class.module_parent::Upstream

      subquery = registry_upstreams_klass
        .where(registry_upstreams_klass.arel_table[:upstream_id].eq(upstream_klass.arel_table[:id]))
        .where.not(registry_id: id)

      upstream_klass
        .primary_key_in(registry_upstreams.select(:upstream_id).unscope(:order))
        .where_not_exists(subquery)
    end

    def purge_cache!
      ::VirtualRegistries::Cache::MarkEntriesForDestructionWorker.bulk_perform_async_with_contexts(
        exclusive_upstreams,
        arguments_proc: ->(upstream) { [upstream.to_global_id.to_s] },
        context_proc: ->(upstream) { { namespace: upstream.group } }
      )
    end

    private

    def delete_upstreams
      exclusive_upstreams.delete_all
    end

    def max_per_group
      return if self.class.for_group(group).count < self.class::MAX_REGISTRY_COUNT

      errors.add(
        :base,
        format(
          n_(
            '%{count} registry is the maximum allowed per top-level group.',
            '%{count} registries is the maximum allowed per top-level group.',
            self.class::MAX_REGISTRY_COUNT
          ),
          count: self.class::MAX_REGISTRY_COUNT
        )
      )
    end
  end
end
