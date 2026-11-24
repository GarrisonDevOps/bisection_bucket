# frozen_string_literal: true

module WebHooks
  class UpdateService
    include Services::ReturnServiceResponses
    include WebHooks::ValidationErrors

    DENIED = 'Insufficient permissions'

    def initialize(current_user)
      @current_user = current_user
    end

    def execute(hook, hook_params)
      return error(DENIED, 403) unless authorized?(hook)

      hook.assign_attributes(hook_params)

      if hook.save
        success({ hook: hook })
      else
        validation_error(hook)
      end
    end

    private

    attr_reader :current_user

    def authorized?(hook)
      Ability.allowed?(current_user, :update_webhook, hook)
    end
  end
end

WebHooks::UpdateService.prepend_mod_with('WebHooks::UpdateService')
