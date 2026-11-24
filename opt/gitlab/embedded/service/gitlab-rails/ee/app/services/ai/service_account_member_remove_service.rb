# frozen_string_literal: true

module Ai
  class ServiceAccountMemberRemoveService
    def initialize(user, membership_container, service_account_user)
      @user = user
      @membership_container = membership_container
      @service_account_user = service_account_user
    end

    def execute
      member = find_or_initialize_member_by_user

      return ServiceResponse.success(message: "Membership not found. Nothing to do.") unless member

      Members::DestroyService.new(
        member,
        current_user: user,
        skip_authorization: true
      ).execute

      ServiceResponse.success
    end

    private

    attr_reader :user, :membership_container, :service_account_user

    def find_or_initialize_member_by_user
      existing_member = membership_container.member(service_account_user)

      return existing_member unless membership_container.is_a?(Group) && !existing_member

      # build a membership so we can run destroy service on subresources
      membership_container.members.build(user: service_account_user)
    end
  end
end
