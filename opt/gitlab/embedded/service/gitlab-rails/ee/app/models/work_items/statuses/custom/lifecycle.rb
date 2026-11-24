# frozen_string_literal: true

module WorkItems
  module Statuses
    module Custom
      class Lifecycle < ApplicationRecord
        self.table_name = 'work_item_custom_lifecycles'

        include WorkItems::Statuses::SharedConstants
        include WorkItems::Statuses::Lifecycle

        MAX_STATUSES_PER_LIFECYCLE = 30
        MAX_LIFECYCLES_PER_NAMESPACE = 50

        belongs_to :namespace
        belongs_to :created_by, class_name: 'User', optional: true
        belongs_to :updated_by, class_name: 'User', optional: true
        belongs_to :default_open_status, class_name: 'WorkItems::Statuses::Custom::Status'
        belongs_to :default_closed_status, class_name: 'WorkItems::Statuses::Custom::Status'
        belongs_to :default_duplicate_status, class_name: 'WorkItems::Statuses::Custom::Status'

        has_many :lifecycle_statuses,
          class_name: 'WorkItems::Statuses::Custom::LifecycleStatus',
          inverse_of: :lifecycle

        has_many :statuses,
          through: :lifecycle_statuses,
          class_name: 'WorkItems::Statuses::Custom::Status'

        has_many :type_custom_lifecycles,
          class_name: 'WorkItems::TypeCustomLifecycle',
          autosave: true

        before_validation :ensure_default_statuses_in_lifecycle

        validates :namespace, :default_open_status, :default_closed_status, :default_duplicate_status, presence: true
        validates :name, presence: true, length: { maximum: 64 }
        validates :name, uniqueness: { scope: :namespace_id }
        validate :validate_default_status_categories
        # Update doesn't change the overall lifecycle per namespace count
        # because you won't be able to change the namespace through the API.
        validate :validate_lifecycles_per_namespace_limit, on: :create
        validate :validate_statuses_limit

        def work_item_types(_namespace = nil)
          lifecycle_provider.types_for(self)
        end

        def work_item_type_ids
          type_custom_lifecycles.map(&:work_item_type_id)
        end

        def work_item_type_ids=(ids)
          self.work_item_types = Array(ids).compact.map(&:to_i)
        end

        def work_item_types=(types)
          # Convert types to an array of IDs for comparison.
          # For custom types converted from system-defined types, #persistable_id
          # returns the converted-from system-defined type id to keep stored
          # references consistent with how work items store work_item_type_id.
          new_type_ids = Array(types).compact.filter_map do |t|
            t.is_a?(Integer) ? t : t.persistable_id
          end.uniq

          unless new_record?
            # Remove associations that are no longer in the list
            type_custom_lifecycles.each do |wt_cf|
              wt_cf.mark_for_destruction unless new_type_ids.include?(wt_cf.work_item_type_id)
            end
          end

          # Add new associations
          existing_type_ids = type_custom_lifecycles.reject(&:marked_for_destruction?).map(&:work_item_type_id)
          new_type_ids.each do |type_id|
            next if existing_type_ids.include?(type_id)

            type_custom_lifecycles.build(work_item_type_id: type_id, namespace: namespace)
          end
        end

        def ordered_statuses
          WorkItems::Statuses::Custom::Status.ordered_for_lifecycle(id)
        end

        def in_use?(namespace_id)
          type_custom_lifecycles.where(namespace_id: namespace_id).exists? ||
            lifecycle_provider.masked_types_for(self).any?
        end

        def has_status_id?(status_id)
          statuses.exists?(id: status_id)
        end

        def default_statuses
          [default_open_status, default_closed_status, default_duplicate_status].compact
        end

        def custom?
          true
        end

        def role_for_status(status)
          return unless status.is_a?(WorkItems::Statuses::Custom::Status)

          if default_open_status_id == status.id
            :open
          elsif default_closed_status_id == status.id
            :closed
          elsif default_duplicate_status_id == status.id
            :duplicate
          end
        end

        private

        def lifecycle_provider
          ::WorkItems::Statuses::Lifecycles::Provider.new(namespace_id)
        end

        def ensure_default_statuses_in_lifecycle
          return unless default_open_status && default_closed_status && default_duplicate_status

          missing_statuses = default_statuses - statuses.to_a

          statuses << missing_statuses if missing_statuses.any?
        end

        def validate_default_status_categories
          return unless default_open_status && default_closed_status && default_duplicate_status

          validate_category(:default_open_status, default_open_status)
          validate_category(:default_closed_status, default_closed_status)
          validate_category(:default_duplicate_status, default_duplicate_status)
        end

        def validate_category(attr_name, default_status)
          valid_categories = DEFAULT_STATUS_CATEGORIES[attr_name]
          return if valid_categories.include?(default_status.category.to_sym)

          errors.add(attr_name, "must be of category #{valid_categories.map(&:to_s).join(' or ')}")
        end

        def validate_statuses_limit
          return unless statuses.present?
          return unless statuses.size > MAX_STATUSES_PER_LIFECYCLE

          errors.add(:base,
            format(_('Lifecycle can only have a maximum of %{limit} statuses.'), limit: MAX_STATUSES_PER_LIFECYCLE)
          )
        end

        def validate_lifecycles_per_namespace_limit
          return unless namespace.present?
          return unless Lifecycle.where(namespace_id: namespace.id).count >= MAX_LIFECYCLES_PER_NAMESPACE

          errors.add(:namespace,
            format(_('can only have a maximum of %{limit} lifecycles.'), limit: MAX_LIFECYCLES_PER_NAMESPACE)
          )
        end
      end
    end
  end
end
