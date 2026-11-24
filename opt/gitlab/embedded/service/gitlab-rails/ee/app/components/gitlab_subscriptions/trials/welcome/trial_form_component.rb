# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    module Welcome
      class TrialFormComponent < ViewComponent::Base
        def initialize(**kwargs)
          @user = kwargs[:user]
          @params = kwargs[:params]
        end

        private

        delegate :page_title, to: :helpers
        attr_reader :user, :params

        def before_render
          content_for :body_class, '!gl-bg-default'
        end

        def role_options
          helpers.role_options.map do |label, value|
            { value: value.to_s, text: label }
          end
        end

        def registration_objective_options
          helpers.shuffled_registration_objective_options.map do |label, value|
            { value: value.to_s, text: label }
          end
        end

        def form_data
          ::Gitlab::Json.generate(
            {
              userData: user_data,
              submitPath: submit_path,
              gtmSubmitEventLabel: 'saasTrialSubmit',
              namespaceId: params[:namespace_id],
              serverValidations: params[:errors] || {},
              roleOptions: role_options,
              registrationObjectiveOptions: registration_objective_options
            }
          )
        end

        def user_data
          {
            firstName: params[:first_name].presence || user.first_name || '',
            lastName: params[:last_name].presence || user.last_name || '',
            showNameFields: user.last_name.blank?,
            emailDomain: user.email_domain,
            companyName: params[:company_name] || user.company,
            country: params[:country] || '',
            state: params[:state] || '',
            groupName: params[:group_name] || '',
            projectName: params[:project_name] || '',
            role: params[:onboarding_status_role] || '',
            setupForCompany: params[:onboarding_status_setup_for_company] || '',
            registrationObjective: params[:onboarding_status_registration_objective] || ''
          }
        end

        def submit_path
          users_sign_up_welcome_path(**params.slice(:step, *::Onboarding::StatusPresenter::GLM_PARAMS))
        end
      end
    end
  end
end
