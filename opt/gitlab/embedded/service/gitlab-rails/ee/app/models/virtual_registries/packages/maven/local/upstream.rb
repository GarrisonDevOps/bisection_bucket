# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      module Local
        class Upstream < ApplicationRecord
          include Gitlab::SQL::Pattern
          include VirtualRegistries::Local

          belongs_to :group
          belongs_to :local_group, class_name: 'Group'
          belongs_to :local_project, class_name: 'Project'

          has_many :registry_upstreams,
            class_name: 'VirtualRegistries::Packages::Maven::RegistryUpstream',
            inverse_of: :local_upstream,
            autosave: true
          has_many :registries, class_name: 'VirtualRegistries::Packages::Maven::Registry', through: :registry_upstreams
          has_many :cache_entries,
            class_name: 'VirtualRegistries::Packages::Maven::Cache::Local::Entry',
            inverse_of: :upstream

          validates :group, top_level_group: true, presence: true
          validates :metadata_cache_validity_hours, numericality: { greater_than: 0, only_integer: true }
          validates :cache_validity_hours, numericality: { greater_than_or_equal_to: 0, only_integer: true }
          validates :name, presence: true, length: { maximum: 255 }
          validates :description, length: { maximum: 1024 }
          validates :local_project_id, uniqueness: { scope: :group_id }, if: :local_project_id?
          validates :local_group_id, uniqueness: { scope: :group_id }, if: :local_group_id?
          validate :ensure_local_project_or_local_group

          scope :for_group, ->(group) { where(group:) }
          scope :for_id_and_group, ->(id:, group:) { where(id:, group:) }
          scope :search_by_name, ->(query) { fuzzy_search(query, [:name], use_minimum_char_limit: false) }
          scope :eager_load_registry_upstream, ->(registry:) {
            eager_load(:registry_upstreams)
              .where(registry_upstreams: { registry: })
              .order('registry_upstreams.position ASC')
          }

          def self.declarative_policy_class
            'VirtualRegistries::Policies::GroupPolicy'
          end

          def destroy_and_sync_positions
            transaction do
              ::VirtualRegistries::Packages::Maven::RegistryUpstream.sync_higher_positions(registry_upstreams)
              destroy
            end
          end

          private

          def ensure_local_project_or_local_group
            return if local_project_id.present? ^ local_group_id.present?

            errors.add(:base, 'should only have either the local group or local project set')
          end
        end
      end
    end
  end
end
