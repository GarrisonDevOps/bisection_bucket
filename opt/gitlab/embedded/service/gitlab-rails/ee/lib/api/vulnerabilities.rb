# frozen_string_literal: true

module API
  class Vulnerabilities < ::API::Base
    include ::API::Helpers::VulnerabilitiesHooks
    include PaginationParams
    include APIGuard

    feature_category :vulnerability_management
    urgency :low

    allow_access_with_scope :ai_workflows, if: ->(request) { request.get? || request.head? }

    helpers ::API::Helpers::VulnerabilitiesHelpers

    helpers do
      def vulnerability
        @vulnerability ||= find_and_authorize_vulnerability!(:read_security_resource)
      end

      def vulnerabilities_by(project)
        ::Security::VulnerabilityReadsFinder.new(project).execute.as_vulnerabilities
      end

      def find_vulnerability!
        Vulnerability.with_findings.find(params[:id])
      end

      def render_vulnerability(vulnerability)
        if vulnerability.valid?
          present vulnerability, with: ::API::Entities::Vulnerability
        else
          render_validation_error!(vulnerability)
        end
      end
    end

    params do
      requires :id, type: String, desc: 'ID of the vulnerability.'
    end
    resource :vulnerabilities do
      before do
        @vulnerability = vulnerability
      end

      desc 'Retrieve a vulnerability' do
        detail 'Retrieves a specified vulnerability.'
        success ::API::Entities::Vulnerability
        tags ['vulnerabilities']
      end
      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :read_vulnerability,
        boundary: -> { vulnerability.project },
        boundary_type: :project
      get ':id' do
        render_vulnerability(@vulnerability)
      end

      desc 'Resolve a vulnerability' do
        detail 'Resolves a specified vulnerability. Returns status code `304` if the vulnerability is already ' \
          'resolved. Returns status code `403` if the authenticated user does not have permission to change the ' \
          'vulnerability status.'
        success ::API::Entities::Vulnerability
        tags ['vulnerabilities']
      end
      params do
        optional :comment,
          type: String,
          desc: 'Comment why vulnerability was reverted to detected (maximum 50,000 characters).'
      end
      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :resolve_vulnerability,
        boundary: -> { vulnerability.project },
        boundary_type: :project
      post ':id/resolve' do
        not_modified! if @vulnerability.resolved?

        @vulnerability = ::Vulnerabilities::ResolveService.new(current_user, @vulnerability, params[:comment]).execute
        render_vulnerability(@vulnerability)
      end

      desc 'Dismiss a vulnerability' do
        detail 'Dismisses a specified vulnerability. Returns status code `304` if the vulnerability is already ' \
          'dismissed. Returns status code `403` if the authenticated user does not have permission to change the ' \
          'vulnerability status.'
        success ::API::Entities::Vulnerability
        tags ['vulnerabilities']
      end
      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :dismiss_vulnerability,
        boundary: -> { vulnerability.project },
        boundary_type: :project
      post ':id/dismiss' do
        not_modified! if @vulnerability.dismissed?

        @vulnerability = ::Vulnerabilities::DismissService.new(current_user, @vulnerability).execute
        render_vulnerability(@vulnerability)
      end

      desc 'Confirm a vulnerability' do
        detail 'Confirms a specified vulnerability, marking it as genuine and requiring action. Returns status code ' \
          '`304` if the vulnerability is already confirmed. Returns status code `403` if the authenticated user ' \
          'does not have permission to change the vulnerability status.'
        success ::API::Entities::Vulnerability
        tags ['vulnerabilities']
      end
      params do
        optional :comment, type: String, desc: 'Comment related to the vulnerability.'
      end
      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :confirm_vulnerability,
        boundary: -> { vulnerability.project },
        boundary_type: :project
      post ':id/confirm' do
        not_modified! if @vulnerability.confirmed?

        @vulnerability = ::Vulnerabilities::ConfirmService.new(current_user, @vulnerability, params[:comment]).execute
        render_vulnerability(@vulnerability)
      end

      desc 'Revert a vulnerability to detected state' do
        detail 'Reverts a specified vulnerability to detected state. Returns status code `304` if the vulnerability ' \
          'is already in detected state. Returns status code `403` if the authenticated user does not have ' \
          'permission to change vulnerability status.'
        success ::API::Entities::Vulnerability
        tags ['vulnerabilities']
      end
      params do
        optional :comment, type: String, desc: 'Comment related to the vulnerability.'
      end
      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :revert_vulnerability,
        boundary: -> { vulnerability.project },
        boundary_type: :project
      post ':id/revert' do
        not_modified! if @vulnerability.detected?

        @vulnerability = ::Vulnerabilities::RevertToDetectedService.new(current_user, @vulnerability,
          params[:comment]).execute
        render_vulnerability(@vulnerability)
      end
    end

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
    end
    resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      desc 'List all project vulnerabilities' do
        detail 'Lists all vulnerabilities for a specified project.'
        success ::API::Entities::Vulnerability
        is_array true
        tags ['vulnerabilities']
      end
      params do
        use :pagination
      end
      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :read_vulnerability, boundary_type: :project
      get ':id/vulnerabilities' do
        authorize! :read_security_resource, user_project

        vulnerabilities = paginate(
          vulnerabilities_by(user_project)
        )

        # Preload representation_information for the page so the entity's
        # secret_redacted? / redacted_as_json checks don't fire a query per row.
        ActiveRecord::Associations::Preloader.new(
          records: vulnerabilities.records,
          associations: :representation_information
        ).call

        present vulnerabilities, with: ::API::Entities::Vulnerability
      end

      desc 'Create a new vulnerability' do
        detail 'Creates a new vulnerability from a confirmed finding.'
        success ::API::Entities::Vulnerability
        tags ['vulnerabilities']
      end
      params do
        requires :finding_id, type: Integer, desc: 'ID of the vulnerability finding to create the vulnerability from.'
      end
      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :create_vulnerability, boundary_type: :project
      post ':id/vulnerabilities' do
        authorize! :admin_vulnerability, user_project

        vulnerability = ::Vulnerabilities::CreateService.new(
          user_project, current_user,
          finding_id: params[:finding_id]
        ).execute

        if vulnerability.persisted?
          present vulnerability, with: ::API::Entities::Vulnerability
        else
          render_validation_error!(vulnerability)
        end
      end
    end
  end
end
