# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    class UltimateCreateService
      include Gitlab::Utils::StrongMemoize

      # Failure/error reasons
      LEAD_FAILED = :lead_failed
      TRIAL_FAILED = :trial_failed
      NAMESPACE_CREATE_FAILED = :namespace_create_failed
      NOT_FOUND = :not_found

      # Flow steps
      FULL = 'full'
      RESUBMIT_LEAD = 'resubmit_lead'
      RESUBMIT_TRIAL = 'resubmit_trial'

      def initialize(step:, params:, user:)
        @step = step
        @params = params
        @user = user
      end

      def execute
        case step
        when FULL
          full_flow
        when RESUBMIT_LEAD
          submit_lead_and_trial
        when RESUBMIT_TRIAL
          resubmit_trial
        else
          not_found
        end
      end

      private

      attr_reader :user, :params, :step, :group_created

      def full_flow
        # For our single step/full flow we have 2 cases:
        # 1. We already have a group, and we can immediately submit the lead and then apply a trial to the group.
        # 2. We don't have a group, and we need to create a group, submit the lead and then apply a trial to the group.
        #    We only want to submit a trial if the group creation is successful.
        #    This will keep us from submitting leads multiple times or a lead being submitted and then a trial
        #    never being applied if the user does not fix any invalid/failed group creations.
        if existing_namespace_provided?
          submit_lead_and_trial
        elsif creating_new_group?
          create_group_and_submit_lead_and_trial
        else
          not_found
        end
      end

      def existing_namespace_provided?
        params[:namespace_id].present? && !GitlabSubscriptions::Trials.creating_group_trigger?(params[:namespace_id])
      end

      def creating_new_group?
        params.key?(:new_group_name)
      end

      def valid_namespace_exists?
        namespace.present?
      end

      def namespace
        namespaces_eligible_for_trial.find_by_id(params[:namespace_id])
      end
      strong_memoize_attr :namespace

      def submit_lead_and_trial
        return not_found unless valid_namespace_exists?

        result = GitlabSubscriptions::CreateLeadService.new.execute({ trial_user: lead_params })

        if result.success?
          track_event('lead_creation_success')
          submit_trial
        else
          track_event('lead_creation_failure')

          ServiceResponse.error(
            message: result.message,
            reason: LEAD_FAILED,
            payload: { namespace_id: namespace.id }
          )
        end
      end

      def lead_params
        attrs = {
          work_email: user.email,
          uid: user.id,
          namespace_id: namespace.id,
          trial_type: GitlabSubscriptions::Trials.trial_type_for_namespace(namespace),
          setup_for_company: user.onboarding_status_setup_for_company,
          skip_email_confirmation: true,
          gitlab_com_trial: true,
          existing_plan: namespace.actual_plan_name,
          provider: 'gitlab'
        }

        params.slice(
          *::Onboarding::StatusPresenter::GLM_PARAMS,
          :company_name, :first_name, :last_name, :phone_number,
          :country, :state
        ).merge(attrs)
      end

      def resubmit_trial
        return not_found unless valid_namespace_exists?

        submit_trial
      end

      def submit_trial
        params[:namespace_id] = namespace.id

        result = GitlabSubscriptions::Trials::ApplyTrialService.new(
          uid: user.id,
          trial_user_information: trial_params
        ).execute

        if result.success?
          track_event('trial_registration_success')

          # Refind the Namespace here due to database sticking logic.
          # Doing this instead of reload/reset of the record ensures we take advantage of the database
          # sticking we performed earlier.
          ServiceResponse.success(message: 'Trial applied', payload: { namespace: Namespace.find(namespace.id) })
        else
          track_event('trial_registration_failure')

          ServiceResponse.error(
            message: result.message,
            reason: result.reason || TRIAL_FAILED,
            payload: { namespace_id: namespace.id }
          )
        end
      end

      def trial_params
        gl_com_params = { gitlab_com_trial: true, sync_to_gl: true }
        namespace_params = {
          namespace: namespace.slice(:id, :name, :path, :kind, :trial_ends_on).merge(plan: namespace.actual_plan.name)
        }

        params.slice(*::Onboarding::StatusPresenter::GLM_PARAMS, :namespace_id)
              .merge(gl_com_params).merge(namespace_params).to_h.symbolize_keys
      end

      def create_group_and_submit_lead_and_trial
        # Instance admins can disable user's ability to create top level groups.
        # See https://docs.gitlab.com/ee/administration/admin_area.html#prevent-a-user-from-creating-groups
        return not_found unless Ability.allowed?(user, :create_group)

        group_params = build_create_group_params
        response = Groups::CreateService.new(user, group_params).execute

        @namespace = response[:group]

        if response.success?
          # We need to stick to the primary database in order to allow the following request
          # fetch the namespace from an up-to-date replica or a primary database.
          ::Namespace.sticking.stick(:namespace, namespace.id)

          submit_lead_and_trial
        else
          ServiceResponse.error(
            message: namespace.errors.full_messages,
            payload: { namespace_id: params[:namespace_id] },
            reason: NAMESPACE_CREATE_FAILED
          )
        end
      end

      def build_create_group_params
        name = ActionController::Base.helpers.sanitize(params[:new_group_name])
        path = Namespace.clean_path(name.parameterize)

        {
          name: name,
          path: path,
          organization_id: params[:organization_id]
        }
      end

      def namespaces_eligible_for_trial
        GitlabSubscriptions::Trials.eligible_namespaces_for_user(user)
      end

      def not_found
        ServiceResponse.error(message: 'Not found', reason: NOT_FOUND)
      end

      def track_event(action)
        Gitlab::InternalEvents.track_event(action, user: user, namespace: namespace)
      end
    end
  end
end
