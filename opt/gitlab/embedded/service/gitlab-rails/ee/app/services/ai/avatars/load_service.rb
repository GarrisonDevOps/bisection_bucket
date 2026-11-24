# frozen_string_literal: true

module Ai
  module Avatars
    class LoadService
      def initialize(item)
        @item = item
      end

      def execute
        return unless avatar_filename

        Users::Internal.bot_avatar(image: avatar_filename)
      rescue Errno::ENOENT => e
        Gitlab::ErrorTracking.track_and_raise_for_dev_exception(e)
        nil
      end

      private

      def avatar_filename
        if @item.third_party_flow?
          'external-agent.png'
        elsif @item.flow? && @item.foundational_flow_reference.present?
          get_foundational_flow_avatar
        elsif @item.flow?
          "custom-flow-#{rand(1..8)}.png"
        end
      end

      def get_foundational_flow_avatar
        @item.foundational_flow&.avatar
      end
    end
  end
end
