# frozen_string_literal: true

module Registrations
  module Welcome
    class FormComponent < ViewComponent::Base
      def initialize(user, params)
        @user = user
        @params = params
      end

      private

      delegate :page_title, to: :helpers
      attr_reader :user, :params

      def registration_type
        ::Onboarding::FreeRegistration
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
            namespaceId: params[:namespace_id],
            serverValidations: params[:errors] || {},
            roleOptions: role_options,
            registrationObjectiveOptions: registration_objective_options,
            setupForCompanyLabel: registration_type.setup_for_company_label_text
          }
        )
      end

      def user_data
        {
          firstName: params[:first_name].presence || user.first_name || '',
          lastName: params[:last_name].presence || user.last_name || '',
          showNameFields: user.last_name.blank?,
          companyName: params[:company_name] || user.company,
          country: default_country,
          state: params[:state] || '',
          groupName: params[:group_name] || '',
          projectName: params[:project_name] || '',
          role: params[:onboarding_status_role] || '',
          setupForCompany: params[:onboarding_status_setup_for_company] || '',
          registrationObjective: params[:onboarding_status_registration_objective] || ''
        }
      end

      def default_country
        return params[:country] if params[:country].present?

        ::Onboarding::DefaultCountry.new(request).code || ''
      end

      # step is threaded back so a resubmit re-enters at the same stage.
      def submit_path
        users_sign_up_welcome_path(**params.slice(:step))
      end
    end
  end
end
