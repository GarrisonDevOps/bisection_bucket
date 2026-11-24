# frozen_string_literal: true

module Members
  class UnassignIssuablesService
    SERVICES = {
      'Issue' => UnassignIssuables::IssuesService,
      'MergeRequest' => UnassignIssuables::MergeRequestsService
    }.freeze

    # @param [User] user user whose membership is being deleted from entity
    # @param [Group, Project] entity
    # @param [User] requesting_user user who initiated the membership deletion of `user`
    def initialize(user, entity, requesting_user)
      @services = SERVICES.transform_values { |service| service.new(user, entity, requesting_user) }
    end

    def execute
      payload = @services.each_value.map { |service| service.execute.payload }.reduce({}, :merge)

      ServiceResponse.success(payload: payload)
    end
  end
end
