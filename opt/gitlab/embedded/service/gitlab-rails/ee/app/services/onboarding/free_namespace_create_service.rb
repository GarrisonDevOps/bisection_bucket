# frozen_string_literal: true

module Onboarding
  class FreeNamespaceCreateService
    include Gitlab::Utils::StrongMemoize

    NAMESPACE_CREATE_FAILED = :namespace_create_failed
    PROJECT_CREATE_FAILED = :project_create_failed
    USER_VALIDATION_FAILED = :user_validation_failed
    NOT_FOUND = :not_found

    FULL = 'full'
    GROUP_FLOW = 'group_flow'
    PROJECT_FLOW = 'project_flow'

    def initialize(params:, user:, step:, namespace_id: nil)
      @params = params
      @user = user
      @step = step
      @namespace_id = namespace_id
    end

    def execute
      case step
      when FULL
        full_flow
      when GROUP_FLOW
        group_flow
      when PROJECT_FLOW
        project_flow
      else
        not_found
      end
    end

    private

    attr_reader :user, :params, :step, :namespace_id, :project

    def namespace
      Namespace.find_by_id(namespace_id)
    end
    strong_memoize_attr :namespace

    def namespace_eligible?
      Ability.allowed?(user, :create_projects, namespace)
    end

    def full_flow
      save_onboarding_status

      if user.errors.none?
        trigger_iterable_creation

        group_flow
      else
        Gitlab::AppJsonLogger.info(class_name: self.class.name, message: 'Free namespace creation failed in user stage')

        ServiceResponse.error(
          message: "Free namespace creation failed in user stage",
          reason: USER_VALIDATION_FAILED,
          payload: { model_errors: {
            role: user.errors[:onboarding_status_role].first,
            setup_for_company: user.errors[:onboarding_status_setup_for_company].first
          }.compact }
        )
      end
    end

    def group_flow
      return not_found unless Ability.allowed?(user, :create_group)

      response = create_group
      @namespace = response[:group]

      if response.success?
        create_project
      else
        error_message = namespace.errors.full_messages.to_sentence

        Gitlab::AppJsonLogger.info(
          class_name: self.class.name,
          message: "Free namespace creation failed in namespace stage: #{error_message}"
        )

        ServiceResponse.error(
          message: "Free namespace creation failed in namespace stage",
          reason: NAMESPACE_CREATE_FAILED,
          payload: { model_errors: { group_name: error_message } }
        )
      end
    end

    def project_flow
      return not_found unless valid_existing_namespace?

      create_project
    end

    def create_group
      name = ActionController::Base.helpers.sanitize(params[:group_name], tags: [])
      create_params = {
        name: name,
        path: Namespace.clean_path(name.parameterize),
        organization_id: params[:organization_id],
        visibility_level: Gitlab::CurrentSettings.default_group_visibility,
        setup_for_company: user.onboarding_status_setup_for_company
      }

      response = Groups::CreateService.new(user, create_params).execute

      if response.success?
        namespace = response[:group]

        ::Groups::CreateEventWorker.perform_async(namespace.id, user.id, 'created')
        ::Gitlab::Tracking.event(self.class.name, 'create_group', namespace: namespace, user: user)
        namespace.namespace_settings.enable_duo_code_review_by_default_pending!

        # Stick to primary so project creation and the redirect don't read a lagging replica.
        ::Namespace.sticking.stick(:namespace, namespace.id)
      end

      response
    end

    def create_project
      return not_found unless user.can_create_project?

      @project = ::Projects::CreateService.new(user, create_project_params).execute

      if project.persisted?
        ::Gitlab::Tracking.event(self.class.name, 'create_project', namespace: project.namespace, user: user)

        success
      else
        error_message = project.errors.full_messages.to_sentence

        Gitlab::AppJsonLogger.info(
          class_name: self.class.name,
          message: "Free namespace creation failed in project stage: #{error_message}"
        )

        ServiceResponse.error(
          message: "Free namespace creation failed in project stage",
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

    def valid_existing_namespace?
      namespace && namespace_eligible?
    end

    def onboarding_user_status
      ::Onboarding::UserStatus.new(user)
    end
    strong_memoize_attr :onboarding_user_status

    def trigger_iterable_creation
      ::Onboarding::CreateIterableTriggerWorker.perform_async(iterable_params.stringify_keys)
    end

    def iterable_params
      {
        provider: 'gitlab',
        create_account: true,
        skip_email_confirmation: true,
        first_name: params[:first_name],
        last_name: params[:last_name],
        company_name: params[:company_name],
        country: params[:country],
        state: params[:state],
        work_email: user.email,
        uid: user.id,
        comment: params[:jobs_to_be_done_other],
        jtbd: user.onboarding_status_registration_objective_name,
        product_interaction: onboarding_user_status.product_interaction,
        opt_in: user.onboarding_status_email_opt_in,
        preferred_language: ::Gitlab::I18n.trimmed_language_name(user.preferred_language),
        setup_for_company: user.onboarding_status_setup_for_company,
        role: user.onboarding_status_role_name
      }
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
      )
    end

    def inject_validators
      class << user
        validates :onboarding_status_role, presence: true
        validates :onboarding_status_setup_for_company, inclusion: { in: [true, false], message: :blank }
      end
    end

    def not_found
      ServiceResponse.error(message: 'Not found', reason: NOT_FOUND)
    end

    def success
      ServiceResponse.success(payload: { project: project })
    end
  end
end
