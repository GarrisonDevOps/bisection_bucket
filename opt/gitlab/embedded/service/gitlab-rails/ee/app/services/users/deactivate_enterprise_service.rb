# frozen_string_literal: true

module Users
  class DeactivateEnterpriseService < DeactivateService
    extend ::Gitlab::Utils::Override

    def initialize(current_user, group:)
      super(current_user)

      @group = group
    end

    private

    attr_reader :group

    override :can_be_deactivated?
    def can_be_deactivated?(user)
      user.enterprise_user_of_group?(group)
    end
  end
end
