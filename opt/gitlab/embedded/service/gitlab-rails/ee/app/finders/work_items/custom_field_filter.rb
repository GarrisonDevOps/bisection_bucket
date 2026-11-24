# frozen_string_literal: true

module WorkItems
  class CustomFieldFilter < ::Issuables::BaseFilter
    def initialize(work_item_id_column: :id, **kwargs)
      @work_item_id_column = work_item_id_column

      super(**kwargs)
    end

    def filter(issuables)
      if params[:custom_field].present?
        issuables = apply_custom_field_filters(issuables, params[:custom_field], :include)
      end

      if not_params && not_params[:custom_field].present?
        issuables = apply_custom_field_filters(issuables, not_params[:custom_field], :exclude)
      end

      if or_params && or_params[:custom_field].present?
        issuables = apply_custom_field_filters(issuables, or_params[:custom_field], :or_include)
      end

      issuables
    end

    private

    def apply_custom_field_filters(issuables, custom_field_params, filter_type)
      return issuables if custom_field_params.blank?
      return issuables if parent && !parent.licensed_feature_available?(:custom_fields)

      custom_field_params.inject(issuables) do |issuables, filter_params|
        custom_field = find_custom_field(filter_params)
        next issuables.none if custom_field.nil?

        filter_by_field_type(issuables, custom_field, filter_params, filter_type)
      end
    end

    def find_custom_field(filter_params)
      if filter_params[:custom_field_id]
        Issuables::CustomField.find_by_id(filter_params[:custom_field_id])
      elsif @parent
        Issuables::CustomField
          .of_namespace(@parent.root_ancestor)
          .find_by_case_insensitive_name(filter_params[:custom_field_name])
      end
    end

    def filter_by_field_type(issuables, custom_field, filter_params, filter_type)
      return issuables.none unless custom_field.field_type_select?

      filter_select_field(issuables, custom_field, filter_params, filter_type)
    end

    def filter_select_field(issuables, custom_field, filter_params, filter_type)
      select_option_ids = get_select_option_ids(custom_field, filter_params)

      if filter_params[:selected_option_ids].nil? &&
          select_option_ids.size != filter_params[:selected_option_values].size

        case filter_type
        when :include
          return issuables.none
        when :exclude
          return issuables
        when :or_include
          # Return none records only when selected options are empty, in any other case we will perform the query.
          return issuables.none if select_option_ids.empty?
        end
      end

      case filter_type
      when :include
        apply_include_filter(issuables, custom_field, select_option_ids)
      when :exclude
        apply_exclude_filter(issuables, custom_field, select_option_ids)
      when :or_include
        apply_or_include_filter(issuables, custom_field, select_option_ids)
      end
    end

    def get_select_option_ids(custom_field, filter_params)
      filter_params[:selected_option_ids] ||
        Issuables::CustomFieldSelectOption.of_field(custom_field)
          .with_case_insensitive_values(filter_params[:selected_option_values])
          .pluck_primary_key
    end

    def apply_include_filter(issuables, custom_field, select_option_ids)
      select_option_ids.inject(issuables) do |issuables, select_option_id|
        issuables.where_exists(matching_select_option_clause(issuables, custom_field, select_option_id))
      end
    end

    def apply_exclude_filter(issuables, custom_field, select_option_ids)
      issuables.where_not_exists(matching_select_option_clause(issuables, custom_field, select_option_ids))
    end

    def apply_or_include_filter(issuables, custom_field, select_option_ids)
      issuables.where_exists(matching_select_option_clause(issuables, custom_field, select_option_ids))
    end

    def matching_select_option_clause(issuables, custom_field, select_option_ids)
      # rubocop: disable CodeReuse/ActiveRecord -- Used only for this filter
      WorkItems::SelectFieldValue.where(
        custom_field_id: custom_field.id,
        custom_field_select_option_id: select_option_ids
      ).where(
        WorkItems::SelectFieldValue.arel_table[:work_item_id].eq(issuables.arel_table[@work_item_id_column])
      )
      # rubocop: enable CodeReuse/ActiveRecord
    end
  end
end
