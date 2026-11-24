# frozen_string_literal: true

module Cd
  module Rollouts
    module WorkflowEvents
      class ChannelTokens
        def initialize(rollout, event)
          @rollout = rollout
          @event = event
        end

        # Unlike the sibling transitions, not keyed to a specific event.type: any
        # event can carry channel_tokens (e.g. a step_started for an approval step
        # that suspends the workflow), so there's nothing to switch on here.
        def execute
          event.channel_tokens.each do |channel_token|
            ::Cd::RolloutChannelToken.upsert_token!(
              rollout: rollout, channel_name: channel_token[:channel_name], token: channel_token[:token],
              rollout_step: step
            )
          end
        end

        private

        attr_reader :rollout, :event

        # The step named by the same event carrying these channel_tokens (e.g. the
        # approval step whose suspension just opened this channel), so a later gate
        # resolution can look its token up exactly rather than guessing. Mirrors
        # Cd::Rollouts::WorkflowEvents::RolloutTransition#step; nil (and so is the
        # persisted rollout_step) when the event names no step, or names one this
        # rollout doesn't have.
        def step
          event.step_path && rollout.rollout_steps.with_path(event.step_path).first
        end
      end
    end
  end
end
