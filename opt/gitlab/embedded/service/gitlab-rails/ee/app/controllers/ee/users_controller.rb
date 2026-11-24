# frozen_string_literal: true

module EE
  module UsersController
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    prepended do
      include GeoInstrumentation

      feature_category :user_profile, [:available_group_templates]

      feature_category :source_code_management, [:available_project_templates]

      urgency :low, [:available_group_templates]
      before_action :ensure_user_is_current_user!, only: [:available_project_templates, :available_group_templates]
    end

    # Even though available templates endpoints accept a user
    # We don't allow fetching the templates for arbitrary user
    # The endpoints are going to be removed in
    # https://gitlab.com/gitlab-org/gitlab/-/issues/345897
    def available_project_templates
      @custom_project_templates =
        user.available_custom_project_templates(search: project_templates_params[:search])
            .page(project_templates_params[:page])

      render layout: false
    end

    def available_group_templates
      @target_group =
        GroupFinder.new(current_user).execute(id: group_templates_params[:group_id])

      # To ensure kaminari can accurately paginate we paginate before
      # grouping, this means kaminari only cares about the projects while the
      # frontend can group the projects by their namespace. The finder
      # returns the projects ordered by namespace_id and
      # id asc. We group the projects by their group which allows the
      # frontend to render sections.
      @group_project_templates =
        ::Projects::GroupTemplatesFinder.new(current_user, group_templates_params[:group_id])
          .execute.page(group_templates_params[:page])
      @groups_with_project_templates = @group_project_templates.group_by(&:group)

      render layout: false
    end

    private

    def project_templates_params
      params.permit(:search, :page)
    end

    def group_templates_params
      params.permit(:group_id, :page)
    end

    override :personal_projects
    def personal_projects
      super.with_compliance_framework_settings
    end

    override :contributed_projects
    def contributed_projects
      super.with_compliance_framework_settings
    end

    override :starred_projects
    def starred_projects
      super.with_compliance_framework_settings
    end

    def ensure_user_is_current_user!
      render_404 unless user == current_user
    end
  end
end
