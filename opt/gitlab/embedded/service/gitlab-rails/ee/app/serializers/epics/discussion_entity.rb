# frozen_string_literal: true

module Epics
  class DiscussionEntity < ::DiscussionEntity
    extend ::Gitlab::Utils::Override

    private

    override :truncated_discussion_path_for
    def truncated_discussion_path_for(discussion)
      noteable = discussion.noteable
      discussions_group_epic_path(noteable.namespace, noteable)
    end

    def expanded?
      true
    end

    def resolved?
      false
    end

    def resolvable?
      false
    end
  end
end
