# frozen_string_literal: true

module Issuables
  class CustomField < ApplicationRecord
    include Gitlab::SQL::Pattern

    MAX_FIELDS = 100
    MAX_ACTIVE_FIELDS = 50
    MAX_ACTIVE_FIELDS_PER_TYPE = 10
    MAX_SELECT_OPTIONS = 50

    FIELD_VALUE_CLASSES = [
      ::WorkItems::TextFieldValue,
      ::WorkItems::NumberFieldValue,
      ::WorkItems::SelectFieldValue,
      ::WorkItems::DateFieldValue
    ].freeze

    enum :field_type, { single_select: 0, multi_select: 1, number: 2, text: 3, date: 4 }, prefix: true

    belongs_to :namespace
    belongs_to :created_by, class_name: 'User', optional: true
    belongs_to :updated_by, class_name: 'User', optional: true
    # rubocop:disable Cop/ActiveRecordDependent -- legacy usage
    has_many :select_options, -> { order(:position, :id) }, dependent: :delete_all, autosave: true,
      # rubocop:enable Cop/ActiveRecordDependent -- legacy usage
      class_name: 'Issuables::CustomFieldSelectOption', inverse_of: :custom_field
    has_many :work_item_type_custom_fields, class_name: 'WorkItems::TypeCustomField', autosave: true

    validates :namespace, :field_type, presence: true
    validates :name, presence: true, length: { maximum: 255 },
      uniqueness: { scope: [:namespace_id], case_sensitive: false }
    validates :select_options, length: {
      maximum: MAX_SELECT_OPTIONS,
      message: ->(*) { _('exceeds the limit of %{count}.') }
    }

    validate :namespace_is_root_group
    validate :number_of_fields_per_namespace
    validate :number_of_active_fields_per_namespace
    validate :number_of_active_fields_per_namespace_per_type
    validate :selectable_field_type_with_select_options

    scope :of_namespace, ->(namespace) { where(namespace_id: namespace) }
    scope :active, -> { where(archived_at: nil) }
    scope :archived, -> { where.not(archived_at: nil) }
    scope :ordered_by_status_and_name, -> { order(Arel.sql('archived_at IS NULL').desc, name: :asc) }
    scope :of_field_type, ->(field_type) { where(field_type: field_type) }

    class << self
      def find_by_case_insensitive_name(name)
        find_by('LOWER(name) = ?', name.downcase)
      end

      def without_any_work_item_types
        where_not_exists(associated_work_item_type_relation)
      end

      def with_work_item_types(work_item_types)
        return without_any_work_item_types if work_item_types.empty?

        where_exists(associated_work_item_type_relation(work_item_type: work_item_types))
      end

      private

      def associated_work_item_type_relation(work_item_type: nil)
        work_item_type_custom_field_table = WorkItems::TypeCustomField.arel_table

        relation = WorkItems::TypeCustomField
          .where(work_item_type_custom_field_table[:namespace_id].eq(arel_table[:namespace_id]))
          .where(work_item_type_custom_field_table[:custom_field_id].eq(arel_table[:id]))

        if work_item_type
          type_ids = Array.wrap(work_item_type).map { |t| t.respond_to?(:persistable_id) ? t.persistable_id : t }
          relation = relation.where(work_item_type_id: type_ids)
        end

        relation
      end
    end

    def work_item_type_ids
      work_item_type_custom_fields.reject(&:marked_for_destruction?).map(&:work_item_type_id)
    end

    def work_item_type_ids=(ids)
      self.work_item_types = Array(ids).compact.map(&:to_i)
    end

    def work_item_types
      work_item_type_custom_fields.map(&:work_item_type).sort_by { |type| type.name.downcase }
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
        work_item_type_custom_fields.each do |wt_cf|
          wt_cf.mark_for_destruction unless new_type_ids.include?(wt_cf.work_item_type_id)
        end
      end

      # Add new associations
      existing_type_ids = work_item_type_custom_fields.reject(&:marked_for_destruction?).map(&:work_item_type_id)
      new_type_ids.each do |type_id|
        next if existing_type_ids.include?(type_id)

        work_item_type_custom_fields.build(work_item_type_id: type_id, namespace: namespace)
      end
    end

    def active?
      archived_at.nil?
    end

    def field_type_select?
      field_type_single_select? || field_type_multi_select?
    end

    # These associations have ordering scopes. We need to reset these when mutated
    # so that the cache is cleared and they are fetched again in the correct order.
    def reset_ordered_associations
      select_options.reset
    end

    private

    def namespace_is_root_group
      return if namespace.nil?
      return if namespace.group_namespace? && namespace.root?

      errors.add(:namespace, _('must be a root group.'))
    end

    def number_of_fields_per_namespace
      return if namespace.nil?
      return unless self.class.of_namespace(namespace).id_not_in(id).count >= MAX_FIELDS

      errors.add(
        :namespace,
        format(_('can only have a maximum of %{limit} custom fields.'), limit: MAX_FIELDS)
      )
    end

    def number_of_active_fields_per_namespace
      return if namespace.nil? || !active?
      return unless self.class.active.of_namespace(namespace).id_not_in(id).count >= MAX_ACTIVE_FIELDS

      errors.add(
        :namespace,
        format(_('can only have a maximum of %{limit} active custom fields.'), limit: MAX_ACTIVE_FIELDS)
      )
    end

    def number_of_active_fields_per_namespace_per_type
      return if namespace.nil? || !active?

      # Get the type IDs we're actually checking (including unsaved changes)
      type_ids = work_item_type_custom_fields
        .reject(&:marked_for_destruction?)
        .filter_map(&:work_item_type_id)

      return if type_ids.empty?

      over_limit_type_ids = self.class.active.of_namespace(namespace)
                              .joins(:work_item_type_custom_fields)
                              .where(work_item_type_custom_fields: { work_item_type_id: type_ids })
                              .where.not(work_item_type_custom_fields: { custom_field_id: id })
                              .group('work_item_type_custom_fields.work_item_type_id')
                              .having('COUNT(*) >= ?', MAX_ACTIVE_FIELDS_PER_TYPE)
                              .pluck('work_item_type_custom_fields.work_item_type_id') # rubocop: disable Database/AvoidUsingPluckWithoutLimit -- results are limited by number of work item types

      return if over_limit_type_ids.blank?

      provider = WorkItems::TypesFramework::Provider.new
      types_by_id = provider.by_ids(over_limit_type_ids).index_by(&:id)

      over_limit_type_ids.each do |wit_id|
        type = types_by_id[wit_id]
        next unless type

        errors.add(
          :base,
          format(_('Work item type %{work_item_type_name} can only have a maximum of %{limit} active custom fields.'),
            work_item_type_name: type.name, limit: MAX_ACTIVE_FIELDS_PER_TYPE)
        )
      end
    end

    def selectable_field_type_with_select_options
      return if field_type_single_select? || field_type_multi_select?
      return if select_options.blank?

      errors.add(:field_type, _('does not support select options.'))
    end
  end
end
