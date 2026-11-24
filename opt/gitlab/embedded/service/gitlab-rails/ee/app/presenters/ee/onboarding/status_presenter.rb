# frozen_string_literal: true

module EE
  module Onboarding
    module StatusPresenter
      extend ::Gitlab::Utils::Override

      GLM_PARAMS = [:glm_source, :glm_content].freeze
      PASSED_THROUGH_PARAMS = [:jobs_to_be_done_other].freeze

      attr_reader :user_return_to

      # string delegations
      delegate :tracking_label, to: :registration_type
      delegate :tracking_label, to: :registration_type, prefix: :preregistration
      delegate :event_label, to: :registration_type
      delegate :account_created_product_interaction, to: :registration_type
      # translation delegations
      delegate :setup_for_company_label_text, to: :registration_type
      delegate :setup_for_company_help_text, to: :registration_type
      delegate :get_started_subtext, to: :registration_type
      delegate :signup_page_image, to: :registration_type
      delegate :signup_page_heading, to: :registration_type
      delegate :identity_verification_panel_image, to: :registration_type
      delegate :identity_verification_panel_heading, to: :registration_type
      # predicate delegations
      delegate :show_joining_project?, to: :registration_type
      delegate :read_from_stored_user_location?, :preserve_stored_location?, to: :registration_type
      delegate :unification_enabled?, :redirect_to_customers_portal?, to: :registration_type
      delegate :trigger_account_created_iterable?, to: :registration_type

      module ClassMethods
        extend ::Gitlab::Utils::Override

        def glm_tracking_params(params)
          params.permit(*GLM_PARAMS)
        end

        def glm_tracking_attributes(params)
          # Converting to a normal hash here to get more predictable
          # behavior with the merge and basic hash behavior as we
          # want to only think about it as a hash here.
          glm_tracking_params(params).to_h
        end

        def passed_through_params(params)
          params.permit(*PASSED_THROUGH_PARAMS)
        end

        override :registration_path_params
        def registration_path_params(params:)
          return super unless ::Onboarding.enabled?

          glm_tracking_attributes(params)
        end
      end

      def self.prepended(base)
        base.singleton_class.prepend(ClassMethods)
      end

      def initialize(*)
        super

        @registration_type = resolve_registration_type
      end

      def welcome_submit_button_text
        return _('Get started!') if oauth?

        # free, trial if not in oauth
        registration_type.welcome_submit_button_text
      end

      def continue_full_onboarding?
        registration_type.continue_full_onboarding? && !oauth? && ::Onboarding.enabled?
      end

      def joining_a_project?
        ::Gitlab::Utils.to_boolean(user.onboarding_status_joining_project, default: false)
      end

      def member_awaiting?
        !!last_invited_member&.awaiting?
      end

      def email_opt_in?
        ::Gitlab::Utils.to_boolean(params[:onboarding_status_email_opt_in], default: true)
      end

      def convert_to_automatic_trial?
        return false unless registration_type.convert_to_automatic_trial?

        setup_for_company?
      end

      def setup_for_company?
        ::Gitlab::Utils.to_boolean(params[:onboarding_status_setup_for_company], default: false)
      end

      override :registration_omniauth_params
      def registration_omniauth_params
        return super unless ::Onboarding.enabled?

        # We don't have controller params here, so we need to slice instead of permit
        super
          .merge(params.slice(*GLM_PARAMS))
          .merge(onboarding_status_email_opt_in: email_opt_in?)
      end

      def trial_registration_omniauth_params
        registration_omniauth_params.merge(trial: true)
      end

      private

      attr_reader :params, :onboarding_user_status, :registration_type

      def resolve_preregistration_type
        return ::Onboarding::InviteRegistration if params[:invite_email]
        return ::Onboarding::SubscriptionSmRegistration if subscription_sm_from_stored_location?
        return ::Onboarding::SubscriptionRegistration if subscription_from_stored_location?
        return ::Onboarding::TrialRegistration if trial?

        ::Onboarding::FreeRegistration
      end

      def resolve_registration_type
        return resolve_preregistration_type unless user&.persisted?

        ::Onboarding::UserStatus.new(user).registration_type
      end

      def oauth?
        # During authorization for oauth, we want to allow it to finish.
        return false unless base_stored_user_location_path.present?

        base_stored_user_location_path == ::Gitlab::Routing.url_helpers.oauth_authorization_path
      end

      def subscription_from_stored_location?
        base_stored_user_location_path == ::Gitlab::Routing.url_helpers.new_subscriptions_path
      end

      def subscription_sm_from_stored_location?
        return false unless ::Onboarding::SubscriptionSmRegistration.unification_enabled?

        subscription_from_stored_location? && stored_user_location_query['deployment_type'] == 'self_managed'
      end

      def trial?
        params[:trial] && ::Onboarding::TrialRegistration.unification_enabled?
      end

      def base_stored_user_location_path
        parsed_stored_user_location.path
      end

      def stored_user_location_query
        Rack::Utils.parse_nested_query(parsed_stored_user_location.query.to_s)
      end

      def parsed_stored_user_location
        URI.parse(user_return_to.to_s)
      end
    end
  end
end
