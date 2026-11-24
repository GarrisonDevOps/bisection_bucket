# frozen_string_literal: true

module WorkItems
  module Statuses
    module Custom
      class Mapping < ApplicationRecord
        include WorkItems::TypesFramework::HasType

        self.table_name = 'work_item_custom_status_mappings'

        belongs_to :namespace
        belongs_to :old_status, class_name: 'WorkItems::Statuses::Custom::Status'
        belongs_to :new_status, class_name: 'WorkItems::Statuses::Custom::Status'

        enum :old_status_role, {
          open: 0,
          closed: 1,
          duplicate: 2
        }, allow_nil: true

        validates :old_status, :new_status, :work_item_type_id, :namespace, presence: true

        validate :statuses_in_same_namespace
        validate :no_self_mapping
        validate :no_chained_mappings
        validate :valid_date_range
        validate :no_overlapping_date_ranges

        scope :with_namespace_id, ->(namespace_id) { where(namespace_id: namespace_id) }
        scope :originating_from_status, ->(namespace:, status:, work_item_type:) {
          type_ids = Array.wrap(work_item_type).map { |t| t.respond_to?(:id) ? t.id : t }
          where(namespace: namespace, old_status: status, work_item_type_id: type_ids)
        }

        def applicable_for?(date)
          (valid_from.nil? || valid_from <= date) && (valid_until.nil? || valid_until > date)
        end

        def time_range
          return unless time_constrained?

          Range.new(valid_from, valid_until)
        end

        def time_constrained?
          valid_from.present? || valid_until.present?
        end

        private

        def statuses_in_same_namespace
          return unless namespace && old_status && new_status
          return if old_status.namespace == namespace && new_status.namespace == namespace

          errors.add(:base, 'statuses must belong to the same namespace as the mapping')
        end

        def no_self_mapping
          return unless old_status_id && new_status_id
          return unless old_status_id == new_status_id

          errors.add(:new_status, 'cannot be the same as old status')
        end

        def no_chained_mappings
          return unless old_status_id && new_status_id

          errors.add(:new_status, 'is already mapped to another status') if mapping_exists_from_new_status?
          errors.add(:old_status, 'is already the target of another mapping') if mapping_exists_to_old_status?
        end

        def mapping_exists_from_new_status?
          self.class.exists?(
            old_status_id: new_status_id,
            namespace_id: namespace_id,
            work_item_type_id: work_item_type_id
          )
        end

        def mapping_exists_to_old_status?
          self.class.exists?(
            new_status_id: old_status_id,
            namespace_id: namespace_id,
            work_item_type_id: work_item_type_id
          )
        end

        def valid_date_range
          return unless valid_from && valid_until
          return unless valid_from >= valid_until

          errors.add(:valid_until, 'must be after valid_from date')
        end

        def no_overlapping_date_ranges
          return unless old_status_id && work_item_type_id && namespace_id

          overlapping = self.class.where(
            namespace_id: namespace_id,
            old_status_id: old_status_id,
            work_item_type_id: work_item_type_id
          ).where.not(id: id)

          overlapping.each do |existing|
            if date_ranges_overlap?(existing)
              errors.add(:base, 'date range overlaps with existing mapping')
              break
            end
          end
        end

        def date_ranges_overlap?(other_mapping)
          # Two ranges overlap if they have any time in common
          # Handle nil dates by treating them as unbounded ranges
          # nil valid_from --> beginning of time, nil valid_until --> end of time
          return false if valid_until && other_mapping.valid_from && valid_until <= other_mapping.valid_from
          return false if other_mapping.valid_until && valid_from && other_mapping.valid_until <= valid_from

          true
        end
      end
    end
  end
end
