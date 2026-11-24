# frozen_string_literal: true

module Ai
  module Messaging
    module Adapters
      class Slack < Base
        class ToolApprovalCard
          APPROVE_ACTION_ID = 'duo_approval_approve'
          DENY_ACTION_ID = 'duo_approval_deny'
          DETAILS_ACTION_ID = 'duo_approval_details'
          DECISIONS = %i[approved denied].freeze

          TITLE_MAX_LENGTH = 150
          SUMMARY_MAX_LENGTH = 900
          INLINE_ARGS_MAX_LENGTH = 1200
          MAX_INLINE_CALLS = 4
          GOAL_PREVIEW_MAX_LENGTH = 80

          START_FLOW_TOOL_NAME = 'start_flow'
          # A custom flow is addressed by consumer ID, so its name is not in the request.
          CATALOG_FLOW_NAME = 'catalog_flow'

          def self.outcome_text(decision)
            if decision == :approved
              s_('DuoSlack|Approved. GitLab Duo is continuing.')
            else
              s_('DuoSlack|Denied. GitLab Duo is continuing without running these actions.')
            end
          end

          def self.title(pending)
            flow = requested_flow(pending)
            return flow_title(flow) if flow

            names = pending.tool_names.uniq.map { |name| display_name(name) }

            format(s_('DuoSlack|Run %{tool_names}'), tool_names: names.join(', '))
              .truncate(TITLE_MAX_LENGTH, separator: ', ')
          end

          # Names the flow and goal of a lone start_flow request for the notification text, since
          # the tool name alone does not tell the user what they approve; nil otherwise.
          def self.flow_request_text(pending)
            flow = requested_flow(pending)
            return unless flow

            goal = flow['goal'].to_s.squish.truncate(GOAL_PREVIEW_MAX_LENGTH, separator: ' ', omission: '…')
            goal = escape_mrkdwn(goal)
            flow_name = escape_mrkdwn(display_name(flow['name']))

            if flow['name'].to_s == CATALOG_FLOW_NAME
              if goal.present?
                format(s_('DuoSlack|GitLab Duo wants to start a custom flow: "%{goal}". Open to approve or deny.'),
                  goal: goal)
              else
                s_('DuoSlack|GitLab Duo wants to start a custom flow. Open to approve or deny.')
              end
            elsif goal.present?
              format(
                s_('DuoSlack|GitLab Duo wants to start the %{flow_name} flow: "%{goal}". Open to approve or deny.'),
                flow_name: flow_name, goal: goal
              )
            else
              format(s_('DuoSlack|GitLab Duo wants to start the %{flow_name} flow. Open to approve or deny.'),
                flow_name: flow_name)
            end
          end

          def self.display_name(tool_name)
            tool_name.to_s.humanize
          end

          # The flow arguments of a request made of exactly one start_flow call.
          def self.requested_flow(pending)
            calls = pending.calls
            return unless calls.one? && calls.first[:name] == START_FLOW_TOOL_NAME

            calls.first[:args]['flow']
          end

          def self.flow_title(flow)
            return s_('DuoSlack|Start a custom flow') if flow['name'].to_s == CATALOG_FLOW_NAME

            format(s_('DuoSlack|Start the %{flow_name} flow'), flow_name: display_name(flow['name']))
              .truncate(TITLE_MAX_LENGTH)
          end

          def self.escape_mrkdwn(text)
            text.to_s.gsub('&', '&amp;').gsub('<', '&lt;').gsub('>', '&gt;')
          end

          private_class_method :requested_flow, :flow_title

          def initialize(pending, workflow_id:, requester_id:)
            @pending = pending
            @workflow_id = workflow_id
            @requester_id = requester_id
          end

          def blocks(decision: nil, decided_by: nil)
            calls = pending.calls.first(MAX_INLINE_CALLS)
            hidden = pending.calls.size - calls.size

            rendered = calls.map { |call| call_blocks(call) }
            truncated = hidden > 0 || rendered.any? { |r| r[:truncated] }

            children = rendered.flat_map { |r| r[:blocks] }
            children << details_block(hidden) if truncated
            children << (decision ? outcome_block(decision, decided_by) : actions_block)

            [{
              type: 'container',
              block_id: "duo_approval_#{pending.fingerprint}",
              width: 'wide',
              is_collapsible: true,
              default_collapsed: decision.present?,
              title: { type: 'plain_text', text: self.class.title(pending) },
              subtitle: { type: 'mrkdwn', text: decision ? outcome_subtitle(decision) : subtitle },
              child_blocks: children
            }]
          end

          private

          attr_reader :pending, :workflow_id, :requester_id

          def value
            "#{workflow_id}:#{pending.fingerprint}"
          end

          def subtitle
            return s_('DuoSlack|Waiting for the person who started this session') if requester_id.blank?

            format(s_('DuoSlack|Waiting for %{requester}'), requester: "<@#{requester_id}>")
          end

          def outcome_subtitle(decision)
            decision == :approved ? s_('DuoSlack|Approved') : s_('DuoSlack|Denied')
          end

          def actions_block
            {
              type: 'actions',
              elements: [
                button(APPROVE_ACTION_ID, s_('DuoSlack|Approve'), 'primary'),
                button(DENY_ACTION_ID, s_('DuoSlack|Deny'), 'danger')
              ]
            }
          end

          def details_block(hidden)
            text =
              if hidden > 0
                format(
                  ns_('DuoSlack|%{count} more action is not shown here.',
                    'DuoSlack|%{count} more actions are not shown here.', hidden),
                  count: hidden
                )
              else
                s_('DuoSlack|The arguments are cut to fit this message.')
              end

            {
              type: 'section',
              text: { type: 'mrkdwn', text: text },
              accessory: button(DETAILS_ACTION_ID, s_('DuoSlack|View full request'))
            }
          end

          def outcome_block(decision, decided_by)
            text =
              if decided_by.blank?
                self.class.outcome_text(decision)
              elsif decision == :approved
                format(s_('DuoSlack|Approved by %{user}. GitLab Duo is continuing.'), user: "<@#{decided_by}>")
              else
                format(
                  s_('DuoSlack|Denied by %{user}. GitLab Duo is continuing without running these actions.'),
                  user: "<@#{decided_by}>"
                )
              end

            { type: 'context', elements: [{ type: 'mrkdwn', text: text }] }
          end

          def call_blocks(call)
            summary = escape_mrkdwn(call[:content].presence || s_('DuoSlack|GitLab Duo wants to run this tool.'))
            truncated = summary.length > SUMMARY_MAX_LENGTH
            summary = summary.truncate(SUMMARY_MAX_LENGTH, separator: ' ', omission: '…') if truncated
            label = escape_mrkdwn(self.class.display_name(call[:name]))

            blocks = [{ type: 'section', text: { type: 'mrkdwn', text: "*#{label}*\n#{summary}" } }]
            return { blocks: blocks, truncated: truncated } if call[:args].blank?

            args = Gitlab::Json.pretty_generate(call[:args])
            if args.length > INLINE_ARGS_MAX_LENGTH
              truncated = true
              args = "#{args.first(INLINE_ARGS_MAX_LENGTH)}\n…"
            end

            blocks << {
              type: 'rich_text',
              elements: [{ type: 'rich_text_preformatted', elements: [{ type: 'text', text: args }] }]
            }

            { blocks: blocks, truncated: truncated }
          end

          def escape_mrkdwn(text)
            self.class.escape_mrkdwn(text)
          end

          def button(action_id, label, style = nil)
            {
              type: 'button',
              action_id: action_id,
              text: { type: 'plain_text', text: label },
              value: value,
              style: style,
              visible_to_user_ids: requester_id.present? ? [requester_id] : nil
            }.compact
          end
        end
      end
    end
  end
end
