# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class AwardEmoji < Grape::Entity
          expose :upvotes,
            documentation: {
              type: 'Integer', example: 5, desc: 'Number of upvotes (thumbs up emoji reactions) on the work item.'
            } do |feature, options|
            options.dig(:award_emoji_counts, feature.work_item.id, :up) || 0
          end

          expose :downvotes,
            documentation: {
              type: 'Integer', example: 1,
              desc: 'Number of downvotes (thumbs down emoji reactions) on the work item.'
            } do |feature, options|
            options.dig(:award_emoji_counts, feature.work_item.id, :down) || 0
          end

          expose :new_custom_emoji_path,
            documentation: {
              type: 'String', example: '/groups/gitlab-org/-/custom_emoji/new',
              desc: "Path to the page for adding a custom emoji to the work item's group. Null if the work " \
                'item is not in a group or the current user cannot create custom emoji there.'
            },
            expose_nil: true do |feature, options|
            feature.new_custom_emoji_path(options[:current_user])
          end
        end
      end
    end
  end
end
