# frozen_string_literal: true

module Authn
  class OauthApplicationPolicy < BasePolicy
    condition(:is_owner) { @subject.owner == @user }

    with_scope :subject
    condition(:instance_application) { @subject.owner.nil? && !@subject.dynamic? }

    condition(:group_owner) { @subject.owner.is_a?(::Group) && can?(:admin_group, @subject.owner) }

    desc "Application is owned by a group where the user can read OAuth applications"
    condition(:group_owner_can_read) do
      group_owned? && can?(:read_oauth_application, @subject.owner)
    end

    desc "Application is owned by a group where the user can update OAuth applications"
    condition(:group_owner_can_update) do
      group_owned? && can?(:update_oauth_application, @subject.owner)
    end

    desc "Application is owned by a group where the user can delete OAuth applications"
    condition(:group_owner_can_delete) do
      group_owned? && can?(:delete_oauth_application, @subject.owner)
    end

    # An instance application has no owner, so is_owner would match a missing user
    rule { anonymous }.prevent_all

    rule { is_owner | group_owner_can_read }.enable :read_oauth_application
    rule { is_owner | group_owner_can_update }.enable :update_oauth_application
    rule { is_owner | group_owner_can_delete }.enable :delete_oauth_application

    rule { is_owner | group_owner | (instance_application & admin) }.enable :update_oauth_application_granular_scope

    private

    def group_owned?
      @subject.owner.is_a?(::Group)
    end
  end
end
