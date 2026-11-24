# frozen_string_literal: true

module Gitlab
  module Timebox
    class BurnchartBuilder < SnapshotBuilder
      TOTAL_FIELDS = %i[scope_count scope_weight completed_count completed_weight].freeze
      NO_CONTRIBUTION = [0, 0, 0, 0].freeze

      UnsupportedEventTypeError = Class.new(StandardError)

      def initialize(timebox, resource_events)
        super

        @contributions = {}
        @totals = NO_CONTRIBUTION
        @ids_to_recompute = Set.new
        @ids_affecting_parents = Set.new
        @ids_affecting_children = Set.new
        @parent_ids_by_child_id = Hash.new { |hash, child_id| hash[child_id] = Set.new }
      end

      private

      def apply_event(event)
        super

        item_id = event['issue_id']

        case event['event_type']
        when ::Timebox::EventAggregationService::EVENT_TYPE[:link]
          @ids_to_recompute << item_id
          @ids_affecting_children << event['value']
          track_parent(event)
        when ::Timebox::EventAggregationService::EVENT_TYPE[:timebox]
          @ids_affecting_parents << item_id
          @ids_affecting_children << item_id
        when ::Timebox::EventAggregationService::EVENT_TYPE[:state],
             ::Timebox::EventAggregationService::EVENT_TYPE[:weight]
          @ids_affecting_parents << item_id
        else
          raise UnsupportedEventTypeError, event['event_type']
        end
      end

      def track_parent(event)
        parent_ids = @parent_ids_by_child_id[event['value']]

        if event['action'] == ::WorkItems::ResourceLinkEvent.actions[:add]
          parent_ids << event['issue_id']
        else
          parent_ids.delete(event['issue_id'])
        end
      end

      def take_snapshot(snapshot_date:)
        ids_to_recompute_for_date.each { |id| update_totals(id) }
        [@ids_to_recompute, @ids_affecting_parents, @ids_affecting_children].each(&:clear)

        @snapshots.push({ date: snapshot_date, **TOTAL_FIELDS.zip(@totals).to_h })
      end

      def ids_to_recompute_for_date
        ids = @ids_to_recompute | @ids_affecting_parents | @ids_affecting_children
        @ids_affecting_parents.each { |id| ids.merge(parent_ids(id)) }
        @ids_affecting_children.each { |id| ids.merge(children_ids(id)) }
        ids
      end

      def parent_ids(child_id)
        @parent_ids_by_child_id.fetch(child_id, [])
      end

      def children_ids(parent_id)
        item_states.dig(parent_id, :children_ids) || []
      end

      def update_totals(id)
        contribution = item_contribution(id)
        previous_contribution = @contributions.fetch(id, NO_CONTRIBUTION)

        @totals = @totals.zip(contribution, previous_contribution)
          .map { |total, added, removed| total + added - removed }
        @contributions[id] = contribution
      end

      def item_contribution(id)
        item = item_states[id]
        return NO_CONTRIBUTION unless in_timebox?(item)
        return issue_contribution(item) if item[:parent_id].nil?
        return NO_CONTRIBUTION if rolled_up_by_parent?(item)

        task_contribution(item)
      end

      def in_timebox?(item)
        item.present? && item[:timebox] == timebox.id
      end

      def rolled_up_by_parent?(task)
        parent = item_states[task[:parent_id]]

        in_timebox?(parent) && parent[:parent_id].nil?
      end

      def task_contribution(task)
        closed?(task) ? [1, task[:weight], 1, task[:weight]] : [1, task[:weight], 0, 0]
      end

      def issue_contribution(issue)
        tasks = rollup_tasks(issue)
        closed_tasks = tasks.select { |task| closed?(task) }
        completed = closed?(issue) && closed_tasks.size == tasks.size
        scope_weight, completed_weight = issue_weights(issue, tasks, closed_tasks)

        [1, scope_weight, completed ? 1 : 0, completed_weight]
      end

      def rollup_tasks(issue)
        issue[:children_ids].filter_map do |child_id|
          task = item_states[child_id]
          task if task && task[:timebox] == issue[:timebox]
        end
      end

      def issue_weights(issue, tasks, closed_tasks)
        if tasks.all? { |task| task[:weight] == 0 }
          [issue[:weight], closed?(issue) ? issue[:weight] : 0]
        else
          [tasks.sum { |task| task[:weight] }, closed_tasks.sum { |task| task[:weight] }]
        end
      end

      def closed?(item)
        item[:state] == ResourceStateEvent.states[:closed]
      end
    end
  end
end
