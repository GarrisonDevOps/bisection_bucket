# frozen_string_literal: true

module Users
  module Pins
    # Appends any missing default pins to each panel a user has saved, once.
    # Panels never saved already fall back to the defaults, so they stay unset. A panel saved as
    # empty gets the defaults too: with unpinned items hidden it would otherwise render no navigation.
    class MergeDefaultsService
      CALLOUT_FEATURE_NAME = Users::CalloutsHelper::TAILORED_NAVIGATION_DEFAULT_PINS_MERGED

      # Merges without saving, so the sidebar can render the result before {#execute} persists it.
      #
      # @return [Hash{String => Array<String>}] the saved pins with missing defaults appended
      def self.merge(saved_pins, defaults_by_panel)
        defaults_by_panel.each_with_object(saved_pins.dup) do |(panel, defaults), pins|
          saved = pins[panel]
          next if saved.nil?

          pins[panel] = saved + (defaults - saved)
        end
      end

      def initialize(user, defaults_by_panel:)
        @user = user
        @defaults_by_panel = defaults_by_panel
        @errors = []
      end

      def execute
        return ServiceResponse.success if Gitlab::Database.read_only?

        saved = Users::Callout.transaction do
          # Claim the callout first so concurrent requests merge at most once,
          # and an invalid merge isn't retried.
          next true unless claim_callout

          save_merged_pins
        end

        return ServiceResponse.success if saved

        ServiceResponse.error(
          message: "Failed to merge default pins: #{errors.to_sentence}",
          reason: :invalid_pins
        )
      end

      private

      attr_reader :user, :defaults_by_panel, :errors

      def save_merged_pins
        pins = self.class.merge(user.pinned_nav_items, defaults_by_panel)
        # Most users have no saved pins, so skip writing an unchanged preference.
        return true if pins == user.pinned_nav_items

        preference = user.user_preference
        return true if preference.update(pinned_nav_items: pins)

        @errors = preference.errors.full_messages
        # Callers like Users::PinsController save this preference again in the same request.
        preference.restore_attributes([:pinned_nav_items])
        false
      end

      def claim_callout
        # Inserts nothing when the callout exists, so a lost race returns no rows.
        Users::Callout.insert(
          {
            user_id: user.id,
            feature_name: Users::Callout.feature_names[CALLOUT_FEATURE_NAME],
            dismissed_at: Time.current
          },
          unique_by: [:user_id, :feature_name],
          returning: :id
        ).rows.any?
      end
    end
  end
end
