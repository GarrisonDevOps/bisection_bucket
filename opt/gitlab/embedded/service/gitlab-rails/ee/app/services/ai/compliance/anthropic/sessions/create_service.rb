# frozen_string_literal: true

module Ai
  module Compliance
    module Anthropic
      module Sessions
        # Records one ai_governance_sessions row per Anthropic local session, so Claude Code
        # sessions appear in the AI Governance UI alongside GitLab Duo ones. `session_data` is
        # a raw session object from Ai::Compliance::Anthropic::Client#local_sessions, so its
        # keys are strings. Identity resolution happens upstream: the user arrives resolved.
        class CreateService
          SOURCE = :claude_code_compliance_api
          # Hyphenated to match Ai::ExternalAgents::AgentIdentity::AGENT_TYPES, while flow_type
          # is not. The two spellings differ on purpose.
          AGENT_TYPE = 'claude-code'
          FLOW_TYPE = 'claude_code'

          def initialize(integration, user:, session_data:)
            @integration = integration
            @user = user
            @session_data = session_data
          end

          def execute
            return ServiceResponse.error(message: 'A resolved user is required', reason: :missing_user) unless user

            if external_xid.blank?
              return ServiceResponse.error(message: 'Upstream session has no id', reason: :missing_external_xid)
            end

            existing = existing_session
            return ServiceResponse.success(payload: { session: existing }) if existing

            ServiceResponse.success(payload: { session: create_session })
          rescue ActiveRecord::RecordNotUnique
            reread_existing
          rescue ActiveRecord::RecordInvalid => e
            # A run that lost the race sees the winning row through the uniqueness validation
            # rather than the index, because the validation queries before the INSERT is sent.
            return reread_existing if e.record.errors.of_kind?(:external_xid, :taken)

            ServiceResponse.error(message: e.message, reason: :invalid_session)
          end

          private

          attr_reader :integration, :user, :session_data

          def create_session
            ::Ai::Governance::Session.create!(
              namespace_id: integration.namespace_id,
              user_id: user.id,
              external_xid: external_xid,
              source: SOURCE,
              # Anthropic gives local sessions no status, so it is final from first sight.
              status: :finished,
              agent_type: AGENT_TYPE,
              flow_type: FLOW_TYPE,
              session_started_at: session_started_at
            )
          end

          def existing_session
            ::Ai::Governance::Session.find_external(
              namespace_id: integration.namespace_id,
              source: SOURCE,
              external_xid: external_xid
            )
          end

          # The winning row already carries the upstream created_at from its own first sight,
          # so reusing it keeps session_started_at stable.
          def reread_existing
            session = existing_session
            return ServiceResponse.success(payload: { session: session }) if session

            ServiceResponse.error(
              message: 'Session conflicted with a row that could not be read back',
              reason: :session_conflict
            )
          end

          def external_xid
            session_data['id']
          end

          # Left nil when unparsable so the presence validation turns it into an error
          # response, rather than an ArgumentError escaping into the caller.
          def session_started_at
            Time.iso8601(session_data['created_at'].to_s)
          rescue ArgumentError
            nil
          end
        end
      end
    end
  end
end
