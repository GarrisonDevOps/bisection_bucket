# frozen_string_literal: true

module EE
  module AwardEmojis
    module AddService
      include ::Gitlab::InternalEventsTracking
      extend ::Gitlab::Utils::Override

      private

      override :after_create
      def after_create(award)
        super

        ::Gitlab::StatusPage.trigger_publish(project, current_user, award)
        track_epic_emoji_awarded(awardable) if awardable.is_a?(Epic)
        track_duo_code_review_reaction(award)
      end

      def track_epic_emoji_awarded(awardable)
        ::Gitlab::UsageDataCounters::EpicActivityUniqueCounter.track_epic_emoji_awarded_action(
          author: current_user,
          namespace: awardable.group
        )
      end

      def track_duo_code_review_reaction(award)
        # Skip if the award is not on a comment created by Duo Code Review and is not a thumbs up or down emoji
        return unless duo_code_review_comment?(award) && award.name.include?('thumbs')

        is_thumbs_up = award.name.start_with?('thumbsup')

        reaction_type = is_thumbs_up ? 'up' : 'down'
        event_name = "react_thumbs_#{reaction_type}_on_duo_code_review_comment"

        track_internal_event(
          event_name,
          user: current_user,
          project: award.awardable.project
        )
      end

      def duo_code_review_comment?(award)
        award.awardable.is_a?(Note) &&
          award.awardable.author.duo_code_review_bot?
      end
    end
  end
end
