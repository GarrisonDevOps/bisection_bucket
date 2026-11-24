# frozen_string_literal: true

module WebHooks
  class CreateService
    include Services::ReturnServiceResponses
    include WebHooks::ValidationErrors

    def initialize(current_user)
      @current_user = current_user
    end

    def execute(hook_params, relation, organization = nil)
      hook = relation.new(hook_params)

      hook.organization_id = organization&.id if hook.is_a?(SystemHook)

      if hook.save
        after_create(hook)
      else
        validation_error(hook)
      end
    end

    private

    def after_create(hook)
      success({ hook: hook, async: false })
    end

    attr_reader :current_user
  end
end

WebHooks::CreateService.prepend_mod_with('WebHooks::CreateService')
