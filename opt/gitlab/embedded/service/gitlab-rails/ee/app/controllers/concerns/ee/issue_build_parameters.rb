# frozen_string_literal: true

module EE
  module IssueBuildParameters
    extend ::Gitlab::Utils::Override

    override :issue_attributes
    def issue_attributes
      attrs = super
      attrs.unshift(:weight) if project.licensed_feature_available?(:issue_weights)
      attrs.unshift(:epic_id) if project.group&.feature_available?(:epics)
      attrs.unshift(:sprint_id) if project.group&.feature_available?(:iterations)

      attrs
    end

    override :issue_params
    def issue_params
      super.tap do |allowed_params|
        if vulnerability_id
          vulnerability_title = format(_("Investigate vulnerability: %{title}"), title: vulnerability.title)

          allowed_params.merge!(
            title: allowed_params.fetch(:title, vulnerability_title),
            description: allowed_params.fetch(:description, render_vulnerability_description),
            confidential: allowed_params.fetch(:confidential, true)
          )
        end
      end
    end

    def render_vulnerability_description
      render_to_string(
        template: 'vulnerabilities/issue_description',
        formats: :md,
        locals: { vulnerability: vulnerability.present }
      )
    end
  end
end
