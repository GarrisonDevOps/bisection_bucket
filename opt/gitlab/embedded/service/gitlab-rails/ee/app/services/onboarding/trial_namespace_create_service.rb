# frozen_string_literal: true

module Onboarding
  class TrialNamespaceCreateService
    include Gitlab::Utils::StrongMemoize

    LEAD_FAILED = :lead_failed
    NAMESPACE_CREATE_FAILED = :namespace_create_failed
    PROJECT_CREATE_FAILED = :project_create_failed
    USER_VALIDATION_FAILED = :user_validation_failed
    NOT_FOUND = :not_found

    # Flow steps
    FULL = 'full'
    GROUP_FLOW = 'group_flow'
    PROJECT_FLOW = 'project_flow'
    LEAD_FLOW = 'lead_flow'
    RESUBMIT_TRIAL = 'resubmit_trial'

    def initialize(params:, user:, step:, namespace_id: nil, project_id: nil)
      @params = params
      @user = user
      @step = step
      @namespace_id = namespace_id
      @project_id = project_id
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
      when RESUBMIT_TRIAL
        resubmit_trial
      else
        not_found
      end
    end

    private

    attr_reader :user, :params, :step, :namespace_id, :project_id

    def namespace
      Namespace.find_by_id(namespace_id)
    end
    strong_memoize_attr :namespace

    def project
      Project.find_by_id(project_id)
    end
    strong_memoize_attr :project

    def onboarding_user_status
      ::Onboarding::UserStatus.new(user)
    end

    def namespace_eligible?
      GitlabSubscriptions::Trials.namespace_eligible?(namespace) && Ability.allowed?(user, :admin_namespace, namespace)
    end

    def full_flow
      save_onboarding_status

      if user.errors.none?
        group_flow
      else
        Gitlab::AppJsonLogger.info(class_name: self.class.name, message: 'Trial creation failed in user stage')

        ServiceResponse.error(
          message: "Trial creation failed in user stage",
          reason: USER_VALIDATION_FAILED,
          payload: { model_errors: {
            role: user.errors[:onboarding_status_role].first
          }.compact }
        )
      end
    end

    def group_flow
      return not_found unless Ability.allowed?(user, :create_group)

      response = create_group
      @namespace = response[:group]

      if response.success?
        create_project_flow
      else
        error_message = namespace.errors.full_messages.to_sentence

        Gitlab::AppJsonLogger.info(
          class_name: self.class.name,
          message: "Trial creation failed in namespace stage: #{error_message}"
        )

        ServiceResponse.error(
          message: "Trial creation failed in namespace stage",
          reason: NAMESPACE_CREATE_FAILED,
          payload: { model_errors: { group_name: error_message } }
        )
      end
    end

    def project_flow
      return not_found unless valid_existing_namespace?

      create_project_flow
    end

    def create_group
      name = ActionController::Base.helpers.sanitize(params[:group_name], tags: [])
      create_params = {
        name: name,
        path: Namespace.clean_path(name.parameterize),
        organization_id: params[:organization_id]
      }

      response = Groups::CreateService.new(user, create_params).execute

      if response.success?
        namespace = response[:group]

        # We need to stick to the primary database in order to allow the following request
        # fetch the namespace from an up-to-date replica or a primary database.
        ::Namespace.sticking.stick(:namespace, namespace.id)
      end

      response
    end

    def create_project_flow
      if project_id.blank?
        return not_found unless user.can_create_project?

        @project = ::Projects::CreateService.new(user, create_project_params).execute
      else
        return not_found unless valid_existing_project?
      end

      if project.persisted?
        submit_lead_and_trial
      else
        error_message = project.errors.full_messages.to_sentence

        Gitlab::AppJsonLogger.info(
          class_name: self.class.name,
          message: "Trial creation failed in project stage: #{error_message}"
        )

        ServiceResponse.error(
          message: "Trial creation failed in project stage",
          reason: PROJECT_CREATE_FAILED,
          payload: { namespace_id: namespace.id, model_errors: { project_name: error_message } }
        )
      end
    end

    def create_project_params
      {
        name: ActionController::Base.helpers.sanitize(params[:project_name], tags: []),
        namespace_id: namespace.id,
        organization_id: namespace.organization_id
      }
    end

    def submit_lead_and_trial
      if submit_lead.success?
        submit_trial

        GitlabSubscriptions::Trials::PendingTrialMarker.set(namespace.id)

        success
      else
        Gitlab::AppJsonLogger.info(class_name: self.class.name, message: 'Trial creation failed in lead stage')

        ServiceResponse.error(
          message: '',
          reason: LEAD_FAILED,
          payload: { namespace_id: namespace.id, project_id: project.id }
        )
      end
    end

    def valid_existing_namespace?
      namespace && namespace_eligible?
    end

    def valid_existing_project?
      project && Ability.allowed?(user, :admin_project, project)
    end

    def valid_existing_namespace_and_project?
      valid_existing_namespace? && valid_existing_project?
    end

    def lead_flow
      return not_found unless valid_existing_namespace_and_project?

      submit_lead_and_trial
    end

    def resubmit_trial
      return not_found unless valid_existing_namespace_and_project?

      submit_trial

      success
    end

    def submit_lead
      GitlabSubscriptions::CreateLeadService.new.execute(trial_user: lead_params)
    end

    def submit_trial
      GitlabSubscriptions::Trials::ApplyTrialWorker.perform_async(user.id, trial_params.deep_stringify_keys)
    end

    def trial_params
      gl_com_params = { gitlab_com_trial: true, sync_to_gl: true }
      namespace_params = {
        namespace_id: namespace.id,
        namespace: namespace.slice(:id, :name, :path, :kind, :trial_ends_on).merge(plan: namespace.actual_plan.name)
      }

      params.slice(*::Onboarding::StatusPresenter::GLM_PARAMS, :namespace_id)
        .merge(gl_com_params).merge(namespace_params).to_h.symbolize_keys
    end

    def lead_params
      attrs = {
        work_email: user.email,
        uid: user.id,
        setup_for_company: user.onboarding_status_setup_for_company,
        skip_email_confirmation: true,
        gitlab_com_trial: true,
        provider: 'gitlab',
        product_interaction: onboarding_user_status.product_interaction,
        role: user.onboarding_status_role_name,
        jtbd: user.onboarding_status_registration_objective_name
      }

      params.slice(
        *::Onboarding::StatusPresenter::GLM_PARAMS,
        :company_name, :country, :state, :first_name, :last_name
      ).merge(attrs)
    end

    def save_onboarding_status
      inject_validators

      user.assign_attributes(onboarding_in_progress: false, **onboarding_params)

      user.save
    end

    def onboarding_params
      params.slice(
        :onboarding_status_role,
        :onboarding_status_setup_for_company,
        :onboarding_status_registration_objective
      ).merge(
        # Only meaningful for the free-to-automatic-trial conversion
        onboarding_status_registration_type: ::Onboarding::REGISTRATION_TYPE[:trial]
      )
    end

    def inject_validators
      class << user
        validates :onboarding_status_role, presence: true
      end
    end

    def not_found
      ServiceResponse.error(message: 'Not found', reason: NOT_FOUND)
    end

    def success
      ServiceResponse.success(
        message: 'Trial applied',
        payload: { namespace: namespace }
      )
    end
  end
end
