# frozen_string_literal: true

module MergeTrains
  class AddMergeRequestService < BaseService
    def initialize(merge_request, current_user, params)
      super(merge_request.target_project, current_user, params)
      @merge_request = merge_request
    end

    def execute
      unless @merge_request.can_be_merged_by?(current_user)
        return ServiceResponse.error(reason: :forbidden, message: "Merge request cannot be merged by current user")
      end

      if @merge_request.auto_merge_enabled?
        return ServiceResponse.error(reason: :conflict, message: "Merge request is already set to Auto-Merge")
      end

      unless @merge_request.target_project.merge_trains_enabled?
        return ServiceResponse.error(reason: :failed, message: "Merge trains are not enabled for this project")
      end

      @merge_request.update!(squash: params[:squash]) if params[:squash]

      auto_merge_service = AutoMergeService.new(@merge_request.target_project, current_user, params.slice(:sha))

      strategy = select_strategy(auto_merge_service)

      return ServiceResponse.error(reason: :failed, message: "No available merge train strategy") unless strategy

      response = auto_merge_service.execute(@merge_request, strategy)

      return ServiceResponse.error(reason: response, message: "Failed to merge") if response == :failed

      ServiceResponse.success(payload: response)
    end

    private

    def select_strategy(auto_merge_service)
      available_strategies = auto_merge_service.available_strategies(@merge_request)

      if params[:auto_merge] &&
          available_strategies.include?(AutoMergeService::STRATEGY_ADD_TO_MERGE_TRAIN_WHEN_CHECKS_PASS)
        return AutoMergeService::STRATEGY_ADD_TO_MERGE_TRAIN_WHEN_CHECKS_PASS
      end

      AutoMergeService::STRATEGY_MERGE_TRAIN if available_strategies.include?(AutoMergeService::STRATEGY_MERGE_TRAIN)
    end
  end
end
