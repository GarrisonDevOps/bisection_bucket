# frozen_string_literal: true

module EE
  module IdeHelper
    extend ::Gitlab::Utils::Override

    private

    override :ide_code_suggestions_data
    def ide_code_suggestions_data
      super.merge({
        'code-suggestions-enabled' => show_code_suggestions? ? 'true' : ''
      })
    end

    def show_code_suggestions?
      Ability.allowed?(current_user, :access_code_suggestions)
    end
  end
end

IdeHelper.prepend_mod
