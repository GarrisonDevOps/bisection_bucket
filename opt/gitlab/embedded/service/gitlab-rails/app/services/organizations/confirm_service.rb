# frozen_string_literal: true

module Organizations
  class ConfirmService
    attr_reader :current_user, :params, :organization

    def initialize(current_user, params = {})
      @current_user = current_user
      @params = params
      @organization = find_organization
    end

    def find_organization
      org = params[:organization]
      return org if org.is_a?(Organizations::Organization)

      Organizations::Organization.find_by_id(params[:organization_id])
    end

    def execute
      return error(_('Organization not found')) unless organization
      return error(_('Insufficient permissions')) unless allowed?

      group_ids = Array(params[:group_ids])

      groups = Group.id_in(group_ids)

      missing_ids = group_ids.map(&:to_i) - groups.map(&:id)
      return error(_('One or more groups could not be found')) if missing_ids.any?

      transfer_result = transfer_groups(groups) if groups.any?
      return transfer_result if transfer_result&.error?

      organization.confirm(confirmed_by_user: current_user)
      return error(organization.errors.full_messages.to_sentence) unless organization.confirmed?

      publish_confirmed_event

      ServiceResponse.success(payload: { organization: organization })
    end

    private

    def transfer_groups(groups)
      Organizations::Transfer::TopLevelGroupService.new(
        groups: groups,
        new_organization: organization,
        current_user: current_user
      ).execute
    end

    def publish_confirmed_event
      Gitlab::EventStore.publish(
        Organizations::ConfirmedEvent.new(data: { organization_id: organization.id })
      )
    end

    def allowed?
      Ability.allowed?(current_user, :update_organization, organization)
    end

    def error(message)
      ServiceResponse.error(message: message, payload: { organization: organization })
    end
  end
end
