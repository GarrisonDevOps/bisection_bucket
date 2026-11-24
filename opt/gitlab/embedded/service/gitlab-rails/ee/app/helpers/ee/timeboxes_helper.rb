# frozen_string_literal: true

module EE
  module TimeboxesHelper
    def can_generate_chart?(milestone)
      return false unless milestone.supports_milestone_charts?

      has_defined_dates?(milestone)
    end

    def show_burndown_alert?(milestone)
      milestone.supports_milestone_charts? &&
        can?(current_user, :admin_milestone, milestone.resource_parent) &&
        (has_no_milestone_issues?(milestone) || !has_defined_dates?(milestone))
    end

    def has_no_milestone_issues?(milestone)
      can_read_project_issue = can?(current_user, :read_issue, milestone.resource_parent)

      can_read_project_issue && milestone_visible_issues_count(milestone) == 0
    end

    def has_defined_dates?(milestone)
      !milestone.start_date.blank? && !milestone.due_date.blank?
    end

    def milestone_weight_tooltip_text(weight)
      if weight == 0
        _("Weight")
      else
        format(_("Weight %{weight}"), weight: weight)
      end
    end

    def first_resource_state_event
      strong_memoize(:first_resource_state_event) { ::ResourceStateEvent.first }
    end

    def legacy_milestone?(milestone)
      first_resource_state_event && milestone.created_at < first_resource_state_event.created_at
    end
  end
end
