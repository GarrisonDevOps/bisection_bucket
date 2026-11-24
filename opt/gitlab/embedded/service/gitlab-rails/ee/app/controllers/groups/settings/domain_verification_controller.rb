# frozen_string_literal: true

module Groups
  module Settings
    class DomainVerificationController < Groups::ApplicationController
      layout 'group_settings'

      before_action :check_feature_availability
      before_action :authorize_admin_group!
      before_action :set_domain, except: [:index, :new, :create]
      before_action :sso_enforcement_redirect, only: [:index, :new]
      before_action :check_verify_rate_limit!, only: :verify

      feature_category :system_access
      urgency :low

      helper_method :domain_presenter

      def index
        @hide_search_settings = true
        @domains = group.all_projects_pages_domains(only_verified: false)
      end

      def new
        @domain = PagesDomain.new
      end

      def create
        @project = find_domain_project(create_params[:project_id])

        if @project.blank?
          error = _('must be specified')
        elsif !@project.pages_enabled?
          error = _('must have Pages enabled')
        end

        if error
          @domain = PagesDomain.new(create_params)
          @domain.errors.add(:project, error)
          render 'new', status: :bad_request
        else
          @domain = ::Pages::Domains::CreateService.new(@project, current_user, create_params).execute

          if @domain&.persisted?
            redirect_to group_settings_domain_verification_path(@group, @domain),
              status: :found,
              notice: s_('DomainVerification|Domain was added')
          else
            render 'new', status: :bad_request
          end
        end
      end

      def show; end

      def update
        service = ::Pages::Domains::UpdateService.new(@domain.project, current_user, update_params)

        if service.execute(@domain)
          redirect_to group_settings_domain_verification_index_path(@group),
            status: :found,
            notice: s_('DomainVerification|Domain was updated')
        else
          render 'show', status: :bad_request
        end
      end

      def destroy
        domain = ::Pages::Domains::DeleteService.new(@domain.project, current_user).execute(@domain)

        respond_to do |format|
          format.html do
            if domain&.destroyed?
              redirect_to group_settings_domain_verification_index_path(@group),
                status: :found,
                notice: s_('DomainVerification|Domain was removed')
            else
              redirect_to group_settings_domain_verification_index_path(@group),
                status: :found,
                alert: s_('DomainVerification|Failed to remove domain')
            end
          end
          format.js
        end
      end

      def verify
        result = VerifyPagesDomainService.new(@domain, current_user).execute

        if result[:status] == :success
          flash[:notice] = s_('DomainVerification|Successfully verified domain ownership')
        else
          flash[:alert] = s_('DomainVerification|Failed to verify domain ownership')
        end

        redirect_to group_settings_domain_verification_path(@group, @domain)
      end

      def retry_auto_ssl
        ::Pages::Domains::RetryAcmeOrderService.new(@domain).execute

        redirect_to group_settings_domain_verification_path(@group, @domain)
      end

      def clean_certificate
        update_params = { user_provided_certificate: nil, user_provided_key: nil }
        service = ::Pages::Domains::UpdateService.new(@domain.project, current_user, update_params)

        flash[:alert] = @domain.errors.full_messages.join(', ') unless service.execute(@domain)

        redirect_to group_settings_domain_verification_path(@group, @domain)
      end

      private

      def check_feature_availability
        render_404 unless group.domain_verification_available?
      end

      def check_verify_rate_limit!
        check_rate_limit!(:pages_domain_verify, scope: { user: current_user }, redirect_back: true)
      end

      def domain_presenter
        @domain_presenter ||= @domain.present(current_user: current_user)
      end

      def find_domain_project(project_id)
        projects = ::GroupProjectsFinder.new(
          group: group,
          current_user: current_user,
          options: { exclude_shared: true, include_subgroups: true }
        ).execute
        projects.find_by_id(project_id)
      end

      def create_params
        @create_params ||= params.require(:pages_domain).permit(:user_provided_key, :user_provided_certificate,
          :domain, :project_id, :auto_ssl_enabled)
      end

      def update_params
        params.permit(pages_domain: [:user_provided_key, :user_provided_certificate, :auto_ssl_enabled])
          .fetch(:pages_domain, ActionController::Parameters.new.permit!)
      end

      def set_domain
        @domain ||= group.all_projects_pages_domains(only_verified: false).find_by_domain!(params.permit(:id)[:id].to_s)
      end

      def sso_enforcement_redirect
        enforce = ::Gitlab::Auth::GroupSaml::SsoEnforcer.new(group.saml_provider, user: current_user).access_restricted?

        redirect_to sso_group_saml_providers_url(group, { redirect: request.fullpath }) if enforce
      end
    end
  end
end
