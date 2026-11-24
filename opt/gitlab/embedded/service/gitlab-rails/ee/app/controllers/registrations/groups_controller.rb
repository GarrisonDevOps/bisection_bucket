# frozen_string_literal: true

module Registrations
  class GroupsController < ApplicationController
    include OneTrustCSP
    include GoogleAnalyticsCSP
    include GoogleSyndicationCSP
    include ::Onboarding::SetRedirect
    include ::Onboarding::InProgress

    skip_before_action :set_confirm_warning
    before_action :verify_onboarding_enabled!
    before_action :verify_in_onboarding_flow!
    before_action :authorize_create_group!, only: :new

    layout 'minimal'

    feature_category :onboarding

    urgency :low, [:create]

    helper_method :tracking_label

    def new
      @group = Group.new(visibility_level: Gitlab::CurrentSettings.default_group_visibility,
        name: "#{current_user.username}-group")
      @project = Project.new(namespace: @group, name: "#{current_user.username}-project")
      @initialize_with_readme = true

      track_event('view_new_group_action', tracking_label)
    end

    def create
      result = service_instance.execute

      if result.success?
        actions_after_success(result.payload)
      else
        @group = result.payload[:group]
        @project = result.payload[:project]

        track_event("track_#{tracking_label}_error", 'failed_creating_group') if @group.errors.present?
        track_event("track_#{tracking_label}_error", 'failed_creating_project') if @project.errors.present?

        unless import? # imports do not have project params
          @template_name = project_params[:template_name]
          @initialize_with_readme = project_params[:initialize_with_readme]
        end

        render :new
      end
    end

    private

    def service_instance
      if import?
        Registrations::ImportNamespaceCreateService
          .new(current_user, group_params: group_params)
      else
        Registrations::StandardNamespaceCreateService
          .new(current_user, group_params: group_params, project_params: project_params)
      end
    end

    def actions_after_success(payload)
      ::Onboarding::FinishService.new(current_user).execute

      if import?
        import_url = URI.join(root_url, general_params[:import_url], "?namespace_id=#{payload[:group].id}").to_s
        redirect_to import_url
      else
        track_project_registration_submission(payload[:project])

        redirect_to new_project_path(namespace_id: payload[:project].namespace_id)
      end
    end

    def authorize_create_group!
      access_denied! unless can?(current_user, :create_group)
    end

    def import?
      general_params[:import_url].present?
    end

    def tracking_label
      onboarding_status_presenter.tracking_label
    end

    def track_event(action, label, project = nil)
      attrs = { user: current_user, label: label, project: project, namespace: project&.namespace }
      ::Gitlab::Tracking.event(self.class.name, action, **attrs.compact)
    end

    def track_project_registration_submission(project)
      track_event('successfully_submitted_form', tracking_label, project)

      template_name = project_params[:template_name]
      return if template_name.blank?

      track_event("select_project_template_#{template_name}", tracking_label, project)
    end

    def onboarding_status_presenter
      ::Onboarding::StatusPresenter.new({}, nil, current_user)
    end
    strong_memoize_attr :onboarding_status_presenter

    def group_params
      params.require(:group).permit(
        :id,
        :name,
        :path,
        :visibility_level,
        :organization_id
      ).with_defaults(organization_id: Current.organization.id)
    end

    def project_params
      params.require(:project).permit(
        :initialize_with_readme,
        :name,
        :namespace_id,
        :path,
        :template_name,
        :visibility_level
      )
    end

    def general_params
      params.permit(:import_url)
    end
  end
end
