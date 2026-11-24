# frozen_string_literal: true

module EE
  module GraphHelper
    extend ::Gitlab::Utils::Override

    override :should_render_quality_summary
    def should_render_quality_summary
      @project.feature_available?(:project_quality_summary) &&
        (::Feature.enabled?(:project_quality_summary_page, @project) ||
          ::Feature.enabled?(:project_quality_summary_page, @project.root_ancestor)
        )
    end
  end
end
