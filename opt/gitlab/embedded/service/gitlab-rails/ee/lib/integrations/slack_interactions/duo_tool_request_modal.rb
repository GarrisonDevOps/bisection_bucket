# frozen_string_literal: true

module Integrations
  module SlackInteractions
    class DuoToolRequestModal
      MAX_BLOCKS = 100
      # Slack caps a modal title at 24 plain_text characters.
      TITLE_MAX_LENGTH = 24
      SECTION_MAX_LENGTH = 3000
      # Slack rejects views past roughly 200 KB with view_too_large; a single
      # rich_text block may hold all of it.
      VIEW_MAX_LENGTH = 180_000

      def self.stale_view
        notice_view(s_('DuoSlack|This approval request has already been answered.'))
      end

      def self.not_owner_view
        notice_view(s_('DuoSlack|Only the person who started this session can view this request.'))
      end

      def self.account_not_linked_view
        notice_view(s_('DuoSlack|Your Slack account is not connected to a GitLab account, ' \
          'so you cannot view this request.'))
      end

      def self.notice_view(text)
        {
          type: 'modal',
          title: title,
          close: { type: 'plain_text', text: s_('DuoSlack|Close') },
          blocks: [section(text)]
        }
      end

      def self.title
        { type: 'plain_text', text: s_('DuoSlack|Full request') }
      end

      def self.section(text)
        { type: 'section', text: { type: 'mrkdwn', text: text } }
      end

      def initialize(pending, session_url: nil)
        @pending = pending
        @session_url = session_url
      end

      def build
        {
          type: 'modal',
          title: { type: 'plain_text', text: title },
          close: { type: 'plain_text', text: s_('DuoSlack|Close') },
          blocks: blocks
        }
      end

      private

      attr_reader :pending, :session_url

      def title
        ::Ai::Messaging::Adapters::Slack::ToolApprovalCard.title(pending).truncate(TITLE_MAX_LENGTH, omission: '…')
      end

      def blocks
        kept = []
        budget = VIEW_MAX_LENGTH
        truncated = false

        pending.calls.each_with_index.flat_map { |call, index| call_blocks(call, index) }.each do |block|
          fitted = kept.size < MAX_BLOCKS - 1 ? fit(block, budget) : nil
          truncated = fitted != block
          break unless fitted

          kept << fitted
          budget -= block_length(fitted)
          break if truncated
        end

        truncated ? overflow(kept) : kept
      end

      def call_blocks(call, index)
        label = escape(::Ai::Messaging::Adapters::Slack::ToolApprovalCard.display_name(call[:name]))
        summary = escape(summary_for(call))

        blocks = []
        blocks << { type: 'divider' } if index > 0
        blocks << self.class.section("*#{label}*\n#{summary}".truncate(SECTION_MAX_LENGTH, separator: ' '))
        blocks << preformatted(Gitlab::Json.pretty_generate(call[:args])) if call[:args].present?
        blocks
      end

      def summary_for(call)
        call[:content].presence || s_('DuoSlack|GitLab Duo wants to run this tool.')
      end

      def preformatted(text)
        { type: 'rich_text', elements: [{ type: 'rich_text_preformatted', elements: [{ type: 'text', text: text }] }] }
      end

      # Only a preformatted block is ever cut, and only so the head of an
      # oversized payload is still shown ahead of the overflow note.
      def fit(block, budget)
        length = block_length(block)
        return block if length <= budget
        return if block[:type] != 'rich_text' || budget < 1000

        preformatted(block[:elements][0][:elements][0][:text].first(budget))
      end

      def block_length(block)
        case block[:type]
        when 'rich_text' then block[:elements][0][:elements][0][:text].length
        when 'section' then block[:text][:text].length
        else 0
        end
      end

      def overflow(kept)
        link = s_('DuoSlack|Open the session in GitLab')
        link = "<#{session_url}|#{link}>" if session_url.present?
        text = format(s_('DuoSlack|The request is too large to show here in full. %{link}.'), link: link)

        kept << { type: 'context', elements: [{ type: 'mrkdwn', text: text }] }
      end

      def escape(text)
        text.gsub('&', '&amp;').gsub('<', '&lt;').gsub('>', '&gt;')
      end
    end
  end
end
