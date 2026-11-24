# frozen_string_literal: true

module Ai
  class FlowTriggersFinder
    MERGE_REQUEST_EVENT_TYPES = %i[merge_request merge_request_ready merge_request_code_conflict].freeze
    LAST_RUN_SORTS = %i[last_run_asc last_run_desc].freeze

    def initialize(project, params = {})
      @project = project
      @params = params
    end

    def execute
      triggers = project.ai_flow_triggers
      triggers = by_ids(triggers)
      triggers = by_kind(triggers)
      triggers = by_active(triggers)
      triggers = by_event_type(triggers)
      triggers = by_search(triggers)
      triggers = with_last_run(triggers)
      triggers = by_last_run_status(triggers)

      sort(triggers)
    end

    private

    attr_reader :project, :params

    def by_ids(triggers)
      return triggers if params[:ids].nil?

      triggers.with_ids(params[:ids])
    end

    def by_kind(triggers)
      case params[:kind]
      when :scheduled then triggers.triggered_on(:scheduled)
      when :event then triggers.not_triggered_on(:scheduled).not_triggered_on(:security_policy)
      else triggers
      end
    end

    def by_active(triggers)
      return triggers if params[:active].nil?

      params[:active] ? triggers.active : triggers.inactive
    end

    def by_event_type(triggers)
      return triggers if params[:event_type].nil?

      event_type = ::Ai::FlowTrigger::EVENT_TYPES_BY_ID[params[:event_type]]
      return triggers.triggered_on_any(MERGE_REQUEST_EVENT_TYPES) if event_type == :merge_request

      triggers.triggered_on(event_type)
    end

    def by_search(triggers)
      return triggers if params[:search].blank?

      triggers.search(params[:search])
    end

    def with_last_run(triggers)
      return triggers unless params[:last_run_status] || LAST_RUN_SORTS.include?(params[:sort])

      triggers.with_last_run(params[:workflows])
    end

    def by_last_run_status(triggers)
      return triggers if params[:last_run_status].nil?

      triggers.with_last_run_status(params[:last_run_status])
    end

    def recent_workflows
      params[:workflows].created_after_in_project(project, ::Ai::FlowTrigger::RUN_STATS_WINDOW.ago)
    end

    def sort(triggers)
      case params[:sort]
      when :last_run_asc then triggers.order_by_last_run(:asc)
      when :last_run_desc then triggers.order_by_last_run(:desc)
      when :total_runs_asc then triggers.order_by_total_runs(recent_workflows, :asc)
      when :total_runs_desc then triggers.order_by_total_runs(recent_workflows, :desc)
      when :name_asc then triggers.order_by_description(:asc)
      when :name_desc then triggers.order_by_description(:desc)
      when :created_asc then triggers.order_by_created(:asc)
      when :updated_asc then triggers.order_by_updated(:asc)
      when :updated_desc then triggers.order_by_updated(:desc)
      else triggers.order_by_created(:desc)
      end
    end
  end
end
