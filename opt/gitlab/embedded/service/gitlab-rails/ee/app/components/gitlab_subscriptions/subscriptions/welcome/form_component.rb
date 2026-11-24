# frozen_string_literal: true

module GitlabSubscriptions
  module Subscriptions
    module Welcome
      class FormComponent < ViewComponent::Base
        def initialize(user, params)
          @user = user
          @params = params
        end

        private

        attr_reader :user, :params

        delegate :page_title, to: :helpers

        def form_data
          ::Gitlab::Json.generate(
            {
              userData: user_data,
              submitPath: submit_path,
              namespaceId: params[:namespace_id],
              serverValidations: params[:errors] || {}
            }
          )
        end

        def user_data
          {
            firstName: params[:first_name].presence || user.first_name || '',
            lastName: params[:last_name].presence || user.last_name || '',
            showNameFields: user.last_name.blank?,
            companyName: params[:company_name] || user.company,
            groupName: params[:group_name] || '',
            projectName: params[:project_name] || ''
          }
        end

        def submit_path
          users_sign_up_welcome_path(step: params[:step])
        end
      end
    end
  end
end
