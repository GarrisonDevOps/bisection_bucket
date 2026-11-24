# frozen_string_literal: true

module ExternalStatusChecks
  class CreateService < BaseService
    attr_reader :skip_authorization

    def execute(skip_authorization: false)
      return access_denied_error unless skip_authorization || authorized?

      external_status_check = container.external_status_checks.new(
        name: params[:name],
        external_url: params[:external_url],
        shared_secret: params[:shared_secret],
        protected_branch_ids: params[:protected_branch_ids]
      )

      if with_audit_logged(external_status_check, 'create_status_check') { external_status_check.save }
        ServiceResponse.success(payload: { external_status_check: external_status_check })
      else
        ServiceResponse.error(
          message: 'Failed to create external status check',
          payload: { errors: external_status_check.errors.full_messages },
          http_status: :unprocessable_entity
        )
      end
    end

    def authorized?
      Ability.allowed?(current_user, :create_external_status_check, container)
    end

    def access_denied_error
      ServiceResponse.error(
        message: 'Failed to create external status check',
        payload: { errors: ['Not allowed'] },
        reason: :access_denied
      )
    end
  end
end
