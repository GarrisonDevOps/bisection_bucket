# frozen_string_literal: true

module API
  module Cd
    # Callback for the CD orchestrator (a Starlark workflow run by AutoFlow in
    # Relay/KAS, not inside the customer's cluster) to report flow-graph
    # progress. Authenticated by a per-rollout bearer token, not a user/PAT.
    class Rollouts < ::API::Base
      feature_category :continuous_delivery
      urgency :low

      TOPIC = ::Cd::Rollouts::WorkflowEventTypes::TOPIC

      # The one event about the rollout rather than a place in its flow, and so the only
      # one that carries no position. The orchestrator fails the flow when a report is not
      # accepted, so refusing this would abort a deploy that had fully succeeded.
      ROLLOUT_SUCCEEDED_TYPE = ::Cd::Rollouts::WorkflowEventTypes::ROLLOUT_SUCCEEDED
      APPROVAL_REQUESTED_TYPE = ::Cd::Rollouts::WorkflowEventTypes::APPROVAL_REQUESTED

      helpers do
        # Decodes `value` into topic/type/data in place, so the rest of the request
        # (declared params, validate_event_params!, the service call) reuses the same
        # flat shape regardless of which one the request used. `data` and `value` are
        # declared via exactly_one_of rather than via Grape's `given`, since the
        # presence check that picks the branch can't also be the check `given` needs.
        def normalize_post_value!
          return unless params[:value]

          decoded = decode_post_value!(params[:value])
          params[:topic] = decoded[:topic]
          params[:type] = decoded[:type]
          params[:data] = decoded[:data]
        end

        # `value` is an AutoFlow Value encoded as protojson (see
        # Gitlab::Kas::Autoflow::ValueConverter#to_value): a dict_value carrying the
        # same topic/type/data shape the flat params carry directly.
        def decode_post_value!(value_hash)
          decoded = ::Gitlab::Kas::Autoflow::ValueConverter.from_value(
            ::Gitlab::Agent::Autoflow::Value.decode_json(::Gitlab::Json.dump(value_hash))
          )
          decoded.is_a?(::Hash) ? decoded.deep_symbolize_keys : {}
        rescue Google::Protobuf::ParseError, ArgumentError => e
          bad_request!("value: #{e.message}")
        end

        def validate_event_params!
          bad_request!('topic is missing or invalid') unless params[:topic] == TOPIC
          bad_request!('type is missing') if params[:type].blank?
          bad_request!('data is missing') unless params[:data].is_a?(::Hash)
        end

        # Checked here rather than declared with `requires`: what makes position optional
        # is the value of `type`, a sibling of `data` rather than of `position` itself,
        # which Grape's `given` cannot reach across.
        def validate_event_position!
          return if params[:type] == ROLLOUT_SUCCEEDED_TYPE || params[:data].key?(:position)

          bad_request!('data[position] is missing')
        end

        # Same reason validate_event_position! isn't a `requires`: what makes these
        # required is the value of `type`, a sibling of `data` and `channel_tokens`
        # rather than of the fields themselves. Without a reason the human has
        # nothing to approve against; without a reply channel backed by a matching
        # token, ResolveGateService has nowhere to push the decision back to.
        def validate_approval_requested_params!
          return unless params[:type] == APPROVAL_REQUESTED_TYPE

          bad_request!('data[reason] is missing') if params[:data][:reason].blank?
          bad_request!('data[reply] is missing') if params[:data][:reply].blank?
          bad_request!('channel_tokens is missing a token for data[reply]') unless reply_channel_token?
        end

        def reply_channel_token?
          Array(params[:channel_tokens]).any? { |token| token[:channel_name] == params[:data][:reply] }
        end

        # Relay sends this on every callback so a redelivered event (it retries on
        # anything short of a 2xx) claims the same Cd::RolloutIncomingEvent row instead
        # of being processed twice. See Cd::Rollouts::ClaimWorkflowEventService.
        def validate_idempotency_key!
          bad_request!('Idempotency-Key header is missing') if idempotency_key.blank?
        end

        def idempotency_key
          headers['Idempotency-Key']
        end

        def find_authenticated_rollout!(id)
          rollout = ::Cd::Rollout.id_in(id).first
          return rollout if rollout && ::Cd::Rollouts::CallbackToken.matches?(rollout_callback_token, rollout)

          ::Cd::Logger.info(message: 'Rejected rollout workflow event callback', rollout_id: id)
          unauthorized!
        end

        def rollout_callback_token
          auth_header = headers['Authorization']
          return unless auth_header&.start_with?('Bearer ')

          auth_header.delete_prefix('Bearer ')
        end
      end

      resource :rollouts do
        desc 'Ingest a rollout workflow event' do
          detail 'Reports flow-graph progress from the CD orchestrator (a Starlark workflow run by AutoFlow).'
          success code: 202, model: ::API::Entities::Cd::Rollout
          failure [
            { code: 400, message: 'Bad request' },
            { code: 401, message: 'Unauthorized' }
          ]
          tags %w[rollouts]
        end
        params do
          requires :id, type: Integer, desc: 'The ID of the rollout', documentation: { example: 1 }
          optional :topic, type: String, desc: 'The event topic'
          optional :type, type: String, limit: 255, desc: 'The event type'
          optional :data, type: Hash, desc: 'The event payload' do
            optional :position, type: Array[Integer],
              desc: 'Zero-based path to the stage/step in the flow definition; required for ' \
                'every event except com.gitlab.cd.rollout_succeeded'
            optional :stage_name, type: String, limit: 255,
              desc: 'Name of the enclosing stage (an environment tier); absent for a step outside any stage'
            optional :environment, type: String, limit: 255,
              desc: 'Exact name of the target GitLab environment; resolves the rollout environment to update ' \
                'when a stage deploys to more than one environment'
            optional :step_type, type: String, limit: 255, desc: 'The step type, present on step_* events'
            optional :service, type: String, limit: 255,
              desc: 'Name of the Cd::Service, present on service_started/service_succeeded/service_failed'
            optional :error, type: String, limit: 2000,
              desc: 'Failure detail, present on step_failed and service_failed'
            optional :reason, type: String, limit: 2000, desc: 'Human-readable prompt, present on approval_requested'
            optional :reply, type: String, limit: 255,
              desc: 'Name of the AutoFlow channel to post the approval decision back into, present on ' \
                'approval_requested'
          end
          optional :value, type: Hash,
            desc: 'AutoFlow Value (protojson), decoded into the same topic/type/data shape as `data` above'
          optional :channel_tokens, type: Array,
            desc: 'AutoFlow channels opened alongside this event, for posting a value back into them later' do
            requires :channel_name, type: String, limit: 255, desc: 'Name of the AutoFlow channel'
            requires :token, type: String, limit: 4096, desc: 'Token used to post a value into the channel'
          end
          exactly_one_of :data, :value
        end
        route_setting :authorization, skip_granular_token_authorization: :cd_rollout_workflow_event
        post ':id' do
          rollout = find_authenticated_rollout!(params[:id])
          normalize_post_value!
          validate_event_params!
          validate_event_position!
          validate_approval_requested_params!
          validate_idempotency_key!

          # Round-tripped through JSON so nested Hashie::Mash/HashWithIndifferentAccess values
          # arrive as plain, Sidekiq-serializable types.
          event_params = ::Gitlab::Json::SafeParser.parse(
            ::Gitlab::Json.dump(declared(params, include_missing: false))
          )

          ::Cd::Rollouts::ClaimWorkflowEventService.new(
            rollout, idempotency_key: idempotency_key, params: event_params
          ).execute

          status :accepted
          present rollout, with: ::API::Entities::Cd::Rollout
        end
      end
    end
  end
end
