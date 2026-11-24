# frozen_string_literal: true

module Onboarding
  class SubscriptionNamespaceCreateService
    include Gitlab::Utils::StrongMemoize

    PRODUCT_INTERACTION = 'Direct Purchase Account Creation Premium Dotcom'
    private_constant :PRODUCT_INTERACTION

    NAMESPACE_CREATE_FAILED = :namespace_create_failed
    PROJECT_CREATE_FAILED = :project_create_failed
    NOT_FOUND = :not_found

    # Flow steps
    FULL = 'full'
    GROUP_FLOW = 'group_flow'
    PROJECT_FLOW = 'project_flow'
    LEAD_FLOW = 'lead_flow'

    def initialize(user:, params:, plan_id:, step:, namespace_id: nil, project_id: nil)
      @user = user
      @params = params
      @plan_id = plan_id
      @namespace_id = namespace_id
      @project_id = project_id
      @step = step
    end

    def execute
      case step
      when FULL
        full_flow
      when GROUP_FLOW
        group_flow
      when PROJECT_FLOW
        project_flow
      when LEAD_FLOW
        lead_flow
      else
        not_found
      end
    end

    private

    attr_reader :user, :params, :plan_id, :step, :namespace_id, :project_id

    def namespace
      Namespace.find_by_id(namespace_id)
    end
    strong_memoize_attr :namespace

    def project
      Project.find_by_id(project_id)
    end
    strong_memoize_attr :project

    def create_group
      name = ActionController::Base.helpers.sanitize(params[:group_name], tags: [])

      create_params = {
        name: name,
        path: Namespace.clean_path(name.parameterize),
        organization_id: params[:organization_id]
      }

      Groups::CreateService.new(user, create_params).execute
    end

    def namespace_eligible?
      Ability.allowed?(user, :admin_namespace, namespace) # rubocop:disable Gitlab/Authz/PermissionCheck -- aligning with what we have in TrialNamespaceCreateService.
    end

    def valid_existing_namespace?
      namespace && namespace_eligible?
    end

    def valid_existing_project?
      project && Ability.allowed?(user, :admin_project, project) # rubocop:disable Gitlab/Authz/PermissionCheck -- aligning with what we have in TrialNamespaceCreateService.
    end

    def valid_existing_namespace_and_project?
      valid_existing_namespace? && valid_existing_project?
    end

    def full_flow
      return not_found unless Ability.allowed?(user, :create_group)
      return not_found unless user.can_create_project?

      group_flow
    end

    def group_flow
      return not_found unless Ability.allowed?(user, :create_group)

      response = create_group
      @namespace = response[:group]

      if response.success?
        create_project_flow
      else
        error_message = namespace.errors.full_messages.to_sentence
        Gitlab::AppJsonLogger.info(class_name: self.class.name, message: "Namespace creation failed: #{error_message}")

        ServiceResponse.error(
          message: "Namespace creation failed",
          reason: NAMESPACE_CREATE_FAILED,
          payload: { model_errors: { group_name: error_message } }
        )
      end
    end

    def project_flow
      return not_found unless valid_existing_namespace?

      create_project_flow
    end

    def create_project_flow
      if project_id.blank?
        return not_found unless user.can_create_project?

        @project = ::Projects::CreateService.new(user, create_project_params).execute
      else
        return not_found unless valid_existing_project?
      end

      if project.persisted?
        submit_lead
      else
        error_message = project.errors.full_messages.to_sentence
        Gitlab::AppJsonLogger.info(class_name: self.class.name, message: "Project creation failed: #{error_message}")

        ServiceResponse.error(
          message: "Project creation failed",
          reason: PROJECT_CREATE_FAILED,
          payload: { namespace_id: namespace.id, model_errors: { project_name: error_message } }
        )
      end
    end

    def lead_flow
      return not_found unless valid_existing_namespace_and_project?

      submit_lead
    end

    def create_project_params
      {
        name: ActionController::Base.helpers.sanitize(params[:project_name], tags: []),
        namespace_id: namespace.id,
        organization_id: namespace.organization_id
      }
    end

    def submit_lead
      persist_company_name

      response = GitlabSubscriptions::CreateHandRaiseLeadService.new(user: user).execute(lead_params)

      if response.success?
        success
      else
        Gitlab::AppJsonLogger.info(class_name: self.class.name, message: 'Lead submission failed')
        ServiceResponse.error(message: '', payload: { namespace_id: namespace.id, project_id: project.id })
      end
    end

    def lead_params
      {
        work_email: user.email,
        opt_in: user.onboarding_status_email_opt_in,
        skip_country_validation: true,
        product_interaction: PRODUCT_INTERACTION,
        plan_id: plan_id,
        first_name: params[:first_name],
        last_name: params[:last_name],
        company_name: params[:company_name]
      }
    end

    # Persisted on the user so it surfaces on /api/v4/user as `organization` and is
    # read by CustomersDot during the OAuth handshake to pre-fill the Customer record
    # (gitlab-org/gitlab#602556). Best-effort: a failure here must not block onboarding,
    # so we log rather than raise or roll back the lead submission that follows.
    def persist_company_name
      return if params[:company_name].blank?
      return if user.update(company: params[:company_name])

      Gitlab::AppJsonLogger.info(
        class_name: self.class.name,
        message: 'Failed to persist company name on user',
        Labkit::Fields::GL_USER_ID => user.id
      )
    end

    def not_found
      ServiceResponse.error(message: 'Not found', reason: NOT_FOUND)
    end

    def success
      ServiceResponse.success(
        message: 'Group and project created',
        payload: { namespace: namespace, project: project }
      )
    end
  end
end
