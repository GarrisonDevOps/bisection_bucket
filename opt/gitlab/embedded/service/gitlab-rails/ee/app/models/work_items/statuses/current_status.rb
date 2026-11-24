# frozen_string_literal: true

module WorkItems
  module Statuses
    class CurrentStatus < ApplicationRecord
      self.table_name = 'work_item_current_statuses'

      include ActiveRecord::FixedItemsModel::HasOne
      include Gitlab::Utils::StrongMemoize

      # TODO: Remove the namespace trigger
      # https://gitlab.com/gitlab-org/gitlab/-/issues/528728
      belongs_to :namespace # set by a trigger
      belongs_to :work_item

      belongs_to_fixed_items :system_defined_status, fixed_items_class: WorkItems::Statuses::SystemDefined::Status
      belongs_to :custom_status, class_name: 'WorkItems::Statuses::Custom::Status', optional: true

      # Set on the unsaved status built for an item without a record. Such items display the
      # current lifecycle default, and mappings only rewrite stored records, so none apply here.
      attr_accessor :fallback

      validate :validate_status_exists
      validate :validate_status_allowed_for_type
      validate :validate_custom_status_allowed_for_lifecycle

      def status
        return find_mapped_status(custom_status_id) || custom_status if custom_status.present?

        converted_status = system_defined_status&.converted_status_in_namespace(top_level_namespace)
        # Handle chained mappings: converted system-defined status -> custom status -> final mapped status
        if converted_status.is_a?(WorkItems::Statuses::Custom::Status)
          return find_mapped_status(converted_status.id) || converted_status
        end

        converted_status
      end

      def status=(new_status)
        case new_status
        when WorkItems::Statuses::SystemDefined::Status
          self.system_defined_status = new_status
          self.custom_status = nil
        when WorkItems::Statuses::Custom::Status
          self.custom_status = new_status
          self.system_defined_status = nil
        end
      end

      private

      def work_item_type
        work_item&.work_item_type
      end
      strong_memoize_attr :work_item_type

      def top_level_namespace
        work_item.namespace.root_ancestor
      end
      strong_memoize_attr :top_level_namespace

      def top_level_namespace_id
        top_level_namespace.id
      end
      strong_memoize_attr :top_level_namespace_id

      def validate_status_exists
        custom_status_enabled? ? validate_custom_status_exists : validate_system_defined_status_exists
      end

      def validate_status_allowed_for_type
        custom_status_enabled? ? validate_custom_status_allowed : validate_system_defined_status_allowed
      end

      def validate_custom_status_allowed_for_lifecycle
        return if custom_status.nil?
        return unless custom_status_enabled?

        lifecycle = work_item_type&.custom_lifecycle_for(top_level_namespace_id)

        return if lifecycle.nil?

        return if lifecycle.statuses.include?(custom_status)

        errors.add(:custom_status, 'is not allowed for this lifecycle')
      end

      # TODO: Pass the namespace once the namespace trigger is removed
      # https://gitlab.com/gitlab-org/gitlab/-/issues/528728
      def custom_status_enabled?
        work_item_type&.custom_status_enabled_for?(top_level_namespace_id)
      end
      strong_memoize_attr :custom_status_enabled?

      def validate_custom_status_exists
        return if custom_status.present?

        errors.add(:custom_status, 'not provided or references non-existent custom status')
      end

      def validate_system_defined_status_exists
        return if system_defined_status.present?

        errors.add(:system_defined_status, 'not provided or references non-existent system defined status')
      end

      def validate_system_defined_status_allowed
        return if system_defined_status.nil?
        return if system_defined_status.allowed_for_work_item?(work_item)

        errors.add(:system_defined_status, 'not allowed for this work item type')
      end

      def validate_custom_status_allowed
        return if custom_status.nil?
        return if custom_status_enabled?

        errors.add(:custom_status, 'not allowed for this work item type')
      end

      def find_mapped_status(status_id)
        return if fallback

        candidate_mappings = cached_status_mappings[[status_id, work_item.work_item_type_id]]
        return if candidate_mappings.nil?

        mapping = candidate_mappings.find { |mapping| mapping.applicable_for?(updated_at) }
        mapping&.new_status
      end

      def cached_status_mappings
        cache_key = "work_items:status_mappings:#{top_level_namespace_id}"

        ::Gitlab::SafeRequestStore.fetch(cache_key) do
          all_mappings = Custom::Mapping
            .with_namespace_id(top_level_namespace_id)

          all_mappings.group_by { |m| [m.old_status_id, m.work_item_type_id] }
        end
      end
    end
  end
end
