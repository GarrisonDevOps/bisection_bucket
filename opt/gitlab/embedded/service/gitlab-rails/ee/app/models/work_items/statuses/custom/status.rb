# frozen_string_literal: true

module WorkItems
  module Statuses
    module Custom
      class Status < ApplicationRecord
        self.table_name = 'work_item_custom_statuses'

        include WorkItems::Statuses::Status
        include ::WorkItems::ConfigurableStatus

        MAX_STATUSES_PER_NAMESPACE = 70
        DISALLOWED_NAME_CHARS = /\A["'`]|["'`]\z|[\x00-\x1F\x7F]/

        enum :category, CATEGORIES

        belongs_to :namespace
        belongs_to :created_by, class_name: 'User', optional: true
        belongs_to :updated_by, class_name: 'User', optional: true

        has_many :lifecycle_statuses,
          class_name: 'WorkItems::Statuses::Custom::LifecycleStatus',
          inverse_of: :status

        has_many :lifecycles,
          through: :lifecycle_statuses,
          class_name: 'WorkItems::Statuses::Custom::Lifecycle'

        scope :in_namespace, ->(namespace) { where(namespace: namespace) }
        scope :ordered_for_lifecycle, ->(lifecycle_id) {
          joins(:lifecycle_statuses)
            .where(work_item_custom_lifecycle_statuses: { lifecycle_id: lifecycle_id })
            .order('work_item_custom_statuses.category ASC,
                    work_item_custom_lifecycle_statuses.position ASC,
                    work_item_custom_statuses.id ASC')
        }

        scope :converted_from_system_defined, -> { where.not(converted_from_system_defined_status_identifier: nil) }

        validates :namespace, :category, presence: true
        validates :name, presence: true, length: { maximum: 32 }
        # Note that currently all statuses are created at root group level, if we would ever want to allow statuses
        # to be created at subgroup level, but unique across groups hierarchy, then this validation would need
        # to be adjusted to compute the uniqueness across hierarchy.
        validates :name, custom_uniqueness: { unique_sql: 'TRIM(BOTH FROM lower(?))', scope: :namespace_id }
        validates :name, format: {
          without: DISALLOWED_NAME_CHARS,
          message: 'cannot start or end with quotes, backticks, or contain control characters'
        }
        validates :color, presence: true, length: { maximum: 7 }, color: true
        validates :description, length: { maximum: 128 }, allow_blank: true
        # Update doesn't change the overall status per namespace count
        # because you won't be able to change the namespace through the API.
        validate :validate_statuses_per_namespace_limit, on: :create

        class << self
          def find_by_namespace_and_name(namespace, name)
            in_namespace(namespace).find_by('TRIM(BOTH FROM LOWER(name)) = TRIM(BOTH FROM LOWER(?))', name)
          end

          def find_by_namespaces_with_partial_name(namespace_ids, name = nil, limit = 100)
            query = where(namespace_id: namespace_ids)

            if name.present?
              sanitized_name = sanitize_sql_like(name.to_s.downcase.strip)
              query = query.where(['TRIM(BOTH FROM LOWER(name)) LIKE ?', "%#{sanitized_name}%"])
            end

            query
              .select(Arel.sql("DISTINCT ON (TRIM(BOTH FROM LOWER(name))) *"))
              .order(Arel.sql("TRIM(BOTH FROM LOWER(name)), id DESC"))
              .limit(limit)
          end

          def find_by_converted_status(status)
            find_by(converted_from_system_defined_status_identifier: status)
          end
        end

        def self.find_by_name_across_namespaces(name, namespace_ids, limit = 100)
          return none if name.blank? || namespace_ids.blank?

          normalized_name = name.strip.downcase

          where(namespace_id: namespace_ids)
            .where('TRIM(BOTH FROM LOWER(name)) = ?', normalized_name)
            .limit(limit)
        end

        def position
          # Temporarily default to 0 as it is not meaningful without lifecycle context
          0
        end

        def in_use_in_lifecycle?(lifecycle)
          return true if direct_usage_exists?(lifecycle)
          return false unless has_system_defined_mapping?

          system_defined_usage_exists?(lifecycle)
        end

        def can_be_deleted_from_namespace?(current_lifecycle)
          namespace = current_lifecycle.namespace
          !used_in_other_lifecycle?(current_lifecycle, namespace) &&
            !in_use_in_lifecycle?(current_lifecycle) &&
            !used_in_mapping?(namespace)
        end

        def used_in_lifecycle_other_than?(excluded_lifecycle_id = nil)
          lifecycles.id_not_in(excluded_lifecycle_id).exists?
        end

        def used_as_mapping_target?(namespace)
          Statuses::Custom::Mapping.exists?(namespace: namespace, new_status: self)
        end

        def shielded_by_open_mapping?(namespace)
          Statuses::Custom::Mapping.exists?(namespace: namespace, old_status: self, valid_until: nil)
        end

        private

        def validate_statuses_per_namespace_limit
          return unless namespace.present?
          return unless Status.where(namespace_id: namespace.id).count >= MAX_STATUSES_PER_NAMESPACE

          errors.add(:namespace,
            format(_('can only have a maximum of %{limit} statuses.'), limit: MAX_STATUSES_PER_NAMESPACE)
          )
        end

        def direct_usage_exists?(lifecycle)
          WorkItem.joins(:current_status)
            .where(
              work_item_type_id: lifecycle.work_item_type_ids,
              work_item_current_statuses: { custom_status: self }
            ).exists?
        end

        def has_system_defined_mapping?
          converted_from_system_defined_status_identifier.present?
        end

        def system_defined_usage_exists?(lifecycle)
          system_defined_status = ::WorkItems::Statuses::SystemDefined::Status.find(
            converted_from_system_defined_status_identifier
          )

          system_defined_status.in_use_in_namespace?(namespace, work_item_type_ids: lifecycle.work_item_type_ids)
        end

        def used_in_other_lifecycle?(lifecycle, namespace)
          lifecycle_statuses
            .where(namespace: namespace)
            .where.not(lifecycle: lifecycle)
            .exists?
        end

        def used_in_mapping?(namespace)
          Statuses::Custom::Mapping.exists?(namespace: namespace, old_status: self)
        end
      end
    end
  end
end
