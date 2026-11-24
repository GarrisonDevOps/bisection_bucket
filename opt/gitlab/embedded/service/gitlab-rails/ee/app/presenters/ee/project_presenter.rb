# frozen_string_literal: true

module EE
  module ProjectPresenter
    extend ::Gitlab::Utils::Override
    extend ::Gitlab::Utils::DelegatorOverride
    include SafeFormatHelper

    # Deprecated with epic https://gitlab.com/groups/gitlab-org/-/epics/19155
    delegator_override :approver_groups
    def approver_groups
      []
    end

    # Deprecated with epic https://gitlab.com/groups/gitlab-org/-/epics/19155
    delegator_override :approvers
    def approvers
      []
    end

    private

    override :storage_anchor_text
    def storage_anchor_text
      if ::Feature.enabled?(:display_cost_factored_storage_size_on_project_pages) && project.forked?
        safe_format(
          _('%{strong_start}%{human_size}%{strong_end} Forked Project'),
          {
            human_size: storage_counter(statistics.cost_factored_storage_size),
            strong_start: '<strong class="project-stat-value">'.html_safe,
            strong_end: '</strong>'.html_safe
          }
        )
      else
        super
      end
    end
  end
end
