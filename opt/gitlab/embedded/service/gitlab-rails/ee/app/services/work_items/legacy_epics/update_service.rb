# frozen_string_literal: true

module WorkItems
  module LegacyEpics
    class UpdateService
      include ErrorMapping

      def self.constructor_container_arg(value)
        # TODO: Dynamically determining the type of a constructor arg based on the class is an antipattern,
        # but this pattern was inherited from Epics::BaseService which this service replaces (via replacing
        # its descendant Epics::UpdateService). The root cause is that the epic services hierarchy had
        # inheritance issues where inheritance may not be the appropriate pattern.
        # See more details in comments below and follow on issue to address this:
        # https://gitlab.com/gitlab-org/gitlab/-/issues/328438

        { group: value }
      end

      # TODO: This service replaces Epics::UpdateService (a descendant of Epics::BaseService) and inherits
      # its constructor pattern issues. The first argument is named group because epics have no `project`
      # associated, even though other similar services take a `project` as the first argument.
      # This pattern exists because named arguments were added after classes were already in use,
      # and `.constructor_container_arg` is used to determine the correct keyword.
      #
      # This reveals an existing inconsistency where sometimes a `project` is passed but ignored,
      # violating the Liskov Substitution Principle
      # (https://en.wikipedia.org/wiki/Liskov_substitution_principle),
      # since we cannot determine which form of constructor to call without knowing the subclass type.
      #
      # This suggests inheritance may not be the proper relationship to "issuable",
      # because it may not be an "is a" relationship. Other `IssuableBaseService` subclasses
      # are in the context of a project and take the project as the first argument.
      #
      # There are concerns like state management and notes which are applicable to epic services,
      # but not necessarily all aspects of issuable services.
      #
      # See the following links for more context:
      # - Original discussion thread: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/59182#note_555401711
      # - Issue to address inheritance problems: https://gitlab.com/gitlab-org/gitlab/-/issues/328438
      def initialize(group:, perform_spam_check: true, current_user: nil, params: {})
        @group = group
        @current_user = current_user
        @params = params.to_hash.symbolize_keys!
        @perform_spam_check = perform_spam_check
      end

      def execute_without_rate_limiting(epic)
        execute(epic, without_rate_limiting: true)
      end

      def execute(epic, without_rate_limiting: false)
        # WorkItems::UpdateService will return an error if we try to assign the same parent twice
        params.delete(:parent_id) if params[:parent_id] == epic&.parent&.id

        return epic unless can_perform_update?(epic)

        transformed_params, widget_params =
          ::Gitlab::WorkItems::LegacyEpics::WidgetParamsExtractor.new(params).extract

        service = ::WorkItems::UpdateService.new(
          container: group,
          perform_spam_check: perform_spam_check,
          current_user: current_user,
          params: transformed_params,
          widget_params: widget_params
        )

        result = without_rate_limiting ? service.execute_without_rate_limiting(epic.issue) : service.execute(epic.issue)

        transform_result(result)
      end

      private

      def transform_result(result)
        new_epic = result[:work_item]&.synced_epic&.reset || Epic.new

        return new_epic if result[:status] == :success

        messages = Array(result[:message])
        messages.each do |msg|
          new_epic.errors.add(:base, msg.include?(WORK_ITEM_NOT_FOUND_ERROR) ? EPIC_NOT_FOUND_ERROR : msg)
        end

        new_epic
      end

      def can_perform_update?(epic)
        return false unless Ability.allowed?(current_user, :update_epic, epic)
        return true unless params[:parent_id]

        Ability.allowed?(current_user, :update_epic, Epic.find(params[:parent_id]))
      end

      attr_reader :group, :current_user, :params, :perform_spam_check
    end
  end
end
