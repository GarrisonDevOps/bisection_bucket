# frozen_string_literal: true

module Gitlab
  module WorkItems
    module LegacyEpics
      class WidgetParamsExtractor
        WORK_ITEM_NOT_FOUND_ERROR = 'No matching work item found'
        EPIC_NOT_FOUND_ERROR = 'No matching epic found. Make sure that you are adding a valid epic URL.'

        MAPPED_WIDGET_PARAMS = {
          description_widget: [:description],
          labels_widget: [:label_ids, :add_label_ids, :remove_label_ids],
          hierarchy_widget: [:parent_id, :parent],
          start_and_due_date_widget: [
            :end_date, :due_date, :due_date_fixed, :due_date_is_fixed, :start_date, :start_date_fixed,
            :start_date_is_fixed
          ],
          color_widget: [:color]
        }.freeze

        def initialize(params)
          @params = params
          @widget_params = {}
        end

        def extract
          work_item_type = ::WorkItems::TypesFramework::Provider.new.find_by_base_type(:epic)

          MAPPED_WIDGET_PARAMS.each do |widget_name, widget_param_keys|
            params_for_widget = params.extract!(*widget_param_keys)

            next if params_for_widget.empty?

            widget_params[widget_name] = case widget_name
                                         when :labels_widget
                                           labels_params(params_for_widget)
                                         when :hierarchy_widget
                                           hierarchy_params(params_for_widget)
                                         when :start_and_due_date_widget
                                           dates_params(params_for_widget)
                                         else
                                           params_for_widget
                                         end
          end

          params[:work_item_type] = work_item_type

          [params, widget_params]
        end

        private

        attr_accessor :params, :widget_params

        def labels_params(epic_params)
          {
            label_ids: epic_params[:label_ids],
            add_label_ids: epic_params[:add_label_ids],
            remove_label_ids: epic_params[:remove_label_ids]
          }
        end

        def hierarchy_params(epic_params)
          if (epic_params.key?(:parent) && epic_params[:parent].nil?) ||
              (epic_params.key?(:parent_id) && epic_params[:parent_id].nil?)
            return { parent: nil }
          end

          parent_work_item = Epic.find_by_id(epic_params[:parent_id] || epic_params[:parent])&.work_item

          return unless parent_work_item

          { parent: parent_work_item }
        end

        def dates_params(epic_params)
          work_item_date_params = {}

          if epic_params.key?(:due_date_is_fixed) || epic_params.key?(:start_date_is_fixed)
            work_item_date_params[:is_fixed] = epic_params[:due_date_is_fixed] || epic_params[:start_date_is_fixed]
          end

          if epic_params.key?(:due_date_fixed)
            work_item_date_params[:due_date] = epic_params[:due_date_fixed]
          elsif epic_params.key?(:end_date)
            work_item_date_params[:due_date] = epic_params[:end_date]
          elsif epic_params.key?(:due_date)
            work_item_date_params[:due_date] = epic_params[:due_date]
          end

          if epic_params.key?(:start_date_fixed)
            work_item_date_params[:start_date] = epic_params[:start_date_fixed]
          elsif epic_params.key?(:start_date)
            work_item_date_params[:start_date] = epic_params[:start_date]
          end

          work_item_date_params
        end
      end
    end
  end
end
