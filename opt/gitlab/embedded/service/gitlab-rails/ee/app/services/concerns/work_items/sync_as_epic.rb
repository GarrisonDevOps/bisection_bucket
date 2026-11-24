# frozen_string_literal: true

module WorkItems
  module SyncAsEpic
    class SyncAsEpicError < StandardError
      attr_reader :http_status

      def initialize(message = nil, http_status = nil)
        super(message)
        @http_status = http_status
      end
    end

    private

    BASE_ATTRIBUTE_PARAMS = %i[
      iid author_id created_at updated_at title title_html description description_html
      confidential state_id last_edited_by_id last_edited_at updated_by_id
      closed_at closed_by_id imported_from
    ].freeze

    def create_epic_for!(work_item)
      Epic.create!(create_params(work_item))
    rescue StandardError => error
      handle_error!(:create, error, work_item)
    end

    def update_epic_for!(work_item)
      epic = work_item.synced_epic
      return true unless epic

      epic.assign_attributes(update_params(work_item).merge(skip_description_version: true))
      epic.save!(touch: false)
    rescue StandardError => error
      handle_error!(:update, error, work_item)
    end

    def create_params(work_item)
      epic_params = {}

      epic_params[:group] = work_item.namespace
      epic_params[:issue_id] = work_item.id
      epic_params[:iid] = work_item.iid

      parent_link = WorkItems::ParentLink.find_by_work_item_id(work_item.id)

      if parent_link && parent_link.work_item_parent.synced_epic
        epic_params[:relative_position] = parent_link.relative_position
        epic_params[:parent_id] = parent_link.work_item_parent.synced_epic.id
        epic_params[:work_item_parent_link_id] = parent_link.id
      end

      epic_params
        .merge(base_attributes_params(work_item))
        .merge(color_params(work_item))
        .merge(dates_params(work_item))
    end

    def update_params(work_item)
      changed_attributes(work_item)
        .intersection(BASE_ATTRIBUTE_PARAMS)
        .index_with { |attr| work_item[attr] }
        .merge(color_params(work_item))
        .merge(dates_params(work_item))
        .merge(updated_at: work_item.updated_at, updated_by_id: work_item.updated_by_id)
    end

    def base_attributes_params(work_item)
      BASE_ATTRIBUTE_PARAMS.index_with { |attr| work_item[attr] }
    end

    def color_params(work_item)
      return {} unless widget_params[:color_widget].present?
      return {} unless work_item.color

      { color: work_item.color.color }
    end

    def dates_params(work_item)
      return {} unless widget_params[:start_and_due_date_widget].present?

      {
        due_date: work_item.dates_source&.due_date,
        due_date_fixed: work_item.dates_source&.due_date_fixed,
        due_date_is_fixed: work_item.dates_source&.due_date_is_fixed,
        start_date: work_item.dates_source&.start_date,
        start_date_fixed: work_item.dates_source&.start_date_fixed,
        start_date_is_fixed: work_item.dates_source&.start_date_is_fixed
      }
    end

    def handle_error!(action, error, work_item)
      ::Gitlab::EpicWorkItemSync::Logger.error(
        message: "Not able to #{action} epic",
        error_message: error.message,
        group_id: work_item.namespace_id,
        work_item_id: work_item&.id
      )

      ::Gitlab::ErrorTracking.track_and_raise_exception(error, group_id: work_item.namespace_id)
    end

    def changed_attributes(work_item)
      strong_memoize_with(:changed_attributes, work_item) do
        work_item.previous_changes.keys.map(&:to_sym)
      end
    end
  end
end
