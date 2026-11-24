# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    class AdvantagesListComponent < ViewComponent::Base
      private

      delegate :sprite_icon, to: :helpers

      def advantages
        [
          s_('InProductMarketing|Invite unlimited colleagues'),
          s_('InProductMarketing|Free guest users'),
          s_('InProductMarketing|Support compliance'),
          s_('InProductMarketing|Built-in security')
        ]
      end

      def heading
        s_('InProductMarketing|Accelerate delivery with GitLab Ultimate + GitLab Duo Agent Platform')
      end
    end
  end
end
