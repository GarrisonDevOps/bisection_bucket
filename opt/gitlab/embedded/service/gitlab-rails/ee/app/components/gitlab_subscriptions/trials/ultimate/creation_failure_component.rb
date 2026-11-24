# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    module Ultimate
      class CreationFailureComponent < ViewComponent::Base
        include SafeFormatHelper

        def initialize(**kwargs)
          @user = kwargs[:user]
          @result = kwargs[:result]
          @eligible_namespaces = kwargs[:eligible_namespaces]
          @params = kwargs[:params]
        end

        def call
          render component_instance
        end

        private

        attr_reader :user, :result, :eligible_namespaces, :params

        def component_instance
          case result.reason
          when GitlabSubscriptions::Trials::UltimateCreateService::NAMESPACE_CREATE_FAILED
            TrialFormWithErrorsComponent.new(
              user: user,
              eligible_namespaces: eligible_namespaces,
              params: params,
              namespace_create_errors: result.errors.to_sentence
            )
          when GitlabSubscriptions::Trials::UltimateCreateService::LEAD_FAILED
            ResubmitComponent.new(
              hidden_fields: lead_failed_hidden_fields,
              submit_path: submit_path(GitlabSubscriptions::Trials::UltimateCreateService::RESUBMIT_LEAD)
            ).with_content(result.errors.to_sentence)
          else
            ResubmitComponent.new(
              hidden_fields: trial_failed_hidden_fields,
              submit_path: submit_path(GitlabSubscriptions::Trials::UltimateCreateService::RESUBMIT_TRIAL)
            ).with_content(trial_error_content)
          end
        end

        def trial_failed_hidden_fields
          { namespace_id: result.payload[:namespace_id] }
        end
        alias_method :namespace_param, :trial_failed_hidden_fields

        def lead_failed_hidden_fields
          params.slice(
            :first_name, :last_name, :company_name, :phone_number, :country, :state
          ).merge(namespace_param)
        end

        def submit_path(step)
          trials_path(
            step: step,
            **params.slice(*::Onboarding::StatusPresenter::GLM_PARAMS)
          )
        end

        def trial_error_content
          if result.reason == GitlabSubscriptions::Trials::ApplyTrialService::GENERIC_TRIAL_ERROR
            safe_format(
              errors_message,
              tag_pair(support_link, :support_link_start, :support_link_end)
            )
          else
            result.errors.to_sentence
          end.concat('.')
        end

        def support_link
          link_to('', Gitlab::Saas.customer_support_url, target: '_blank', rel: 'noopener noreferrer')
        end

        def errors_message
          support_message = _(
            'Please reach out to %{support_link_start}GitLab Support%{support_link_end} for assistance'
          )

          [support_message, result.errors.to_sentence.presence].compact.join(': ')
        end
      end
    end
  end
end
