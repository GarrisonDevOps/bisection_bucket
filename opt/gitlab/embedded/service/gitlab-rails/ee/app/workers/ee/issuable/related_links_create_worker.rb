# frozen_string_literal: true

module EE
  module Issuable
    module RelatedLinksCreateWorker
      extend ::Gitlab::Utils::Override

      private

      override :create_notes
      def create_notes
        case params[:link_type]
        when ::IssuableLink::TYPE_BLOCKS
          create_blocking_notes
        when ::IssuableLink::TYPE_IS_BLOCKED_BY
          create_blocked_by_notes
        else
          super
        end
      end

      def create_blocking_notes
        errors = links.filter_map { |link| create_system_note(link.target, link.source, :blocked_by_issuable) }
        errors << create_system_note(issuable, links.collect(&:target), :block_issuable)
      end

      def create_blocked_by_notes
        errors = links.filter_map { |link| create_system_note(link.source, link.target, :block_issuable) }
        errors << create_system_note(issuable, links.collect(&:source), :blocked_by_issuable)
      end
    end
  end
end
