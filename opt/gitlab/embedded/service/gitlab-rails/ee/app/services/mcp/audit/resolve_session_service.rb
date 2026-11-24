# frozen_string_literal: true

module Mcp
  module Audit
    # Resolves the inferred session a tool call belongs to.
    #
    # MCP is stateless - session ids were removed from the specification in the
    # 2026-07-28 revision - so sessions are inferred from caller identity plus a
    # sliding time window rather than read off the request.
    class ResolveSessionService
      include ::Gitlab::Utils::StrongMemoize

      IDLE_EXTENSION = 15.minutes
      MAX_DURATION = 30.minutes
      UNKNOWN_AGENT = 'unknown'
      DYNAMIC_APP_NAME_PREFIX = '[Unverified Dynamic Application] '
      # Maps the client's declared OAuth application name onto a canonical slug,
      # so one agent cannot appear under two spellings in `agent_type`-grouped
      # analytics or miss the frontend's exact-key lookup. Shared value space with
      # `Ai::ExternalAgents::AgentIdentity::AGENT_TYPES` and `glab`-driven sessions.
      #
      # Ordered: the first match wins. Short names are anchored on word
      # boundaries because an unanchored one matches inside unrelated names:
      # /cursor/ claims "Precursor AI" and /codex/ claims "Codexity".
      AGENT_PATTERNS = {
        'claude-code' => /claude[\s_-]*code/i,
        'opencode' => /open[\s_-]*code/i,
        'cursor' => /\bcursor\b/i,
        'codex' => /\bcodex\b/i
      }.freeze
      OPEN_SESSIONS_KEY = 'mcp:audit:open'

      # @param container [Project, Namespace] what the session is scoped to.
      def initialize(current_user:, container:)
        @current_user = current_user
        @container = container
      end

      # @return [Ai::Governance::Session, nil] nil when no session could be
      #   resolved, in which case the caller skips auditing rather than failing
      #   the tool call.
      def execute
        return unless current_user && container

        state = read_state
        return resume(state) if state && within_window?(state)

        # Unconditional, because a key we cannot use is worse than no key: it
        # would fail the SET NX in `claim` and wedge this caller until the TTL
        # expired. Two callers racing here can each discard and mint, so a
        # duplicate session at the window boundary is accepted rather than
        # paying for a compare-and-delete on every call.
        discard_state
        mint
      end

      private

      attr_reader :current_user, :container

      def project
        container if container.is_a?(::Project)
      end

      # `ai_governance_sessions.namespace_id` is the sharding key and is NOT NULL,
      # and project-scoped rows store the project namespace id so a group
      # hierarchy lookup stays a single `namespace_id IN (...)`. `project_id` is
      # recorded alongside it, which is what the audit event's own scope uses.
      def namespace_id
        project ? project.project_namespace_id : container.id
      end

      # The OAuth application behind the request is the only agent identity that
      # survives MCP's statelessness: `clientInfo` arrives on `initialize` and
      # cannot be correlated to a later `tools/call`. Personal access tokens
      # carry no application, so those callers collapse into one session per
      # user and are recorded as `unknown`.
      def application_id
        ::Current.token_info&.dig(:token_application_id)
      end
      strong_memoize_attr :application_id

      def lookup_key
        "mcp:audit:session:#{current_user.id}:#{application_id || 'pat'}:#{container.class.name}:#{container.id}"
      end

      def read_state
        raw = with_redis { |redis| redis.get(lookup_key) }
        return if raw.blank?

        state = ::Gitlab::Json::SafeParser.parse(raw)
        return unless state.is_a?(Hash) && state['session_id'] && state['started_at'] && state['expires_at']

        state
      rescue ::JSON::ParserError
        nil
      end

      # Both bounds are evaluated in Ruby rather than left to the Redis TTL: the
      # TTL is a cleanup mechanism, not the source of truth, so a key that
      # outlives its window cannot silently extend a session.
      def within_window?(state)
        now = Time.current

        now.to_i < state['expires_at'].to_i &&
          now < Time.zone.at(state['started_at'].to_i) + MAX_DURATION
      end

      def resume(state)
        session = ::Ai::Governance::Session.find_by_id(state['session_id'])
        # The row was removed underneath us. The stale key would block the NX
        # claim below, so drop it before starting a fresh window.
        unless session
          discard_state
          return mint
        end

        write_state(session, started_at: state['started_at'].to_i)
        session
      end

      def discard_state
        with_redis { |redis| redis.del(lookup_key) }
      end

      # Builds the row first and claims the key second. Losing the claim leaves a
      # short-lived orphan row that is destroyed immediately, which is preferable
      # to reserving the key first and leaving the losing tool call unaudited.
      # `Gitlab::ExclusiveLease#in_lock` is deliberately not used here: it sleeps
      # between retries and is documented as unsuitable for a webserver thread.
      def mint
        session = create_session

        unless claim(session)
          session.destroy
          return resume_after_lost_claim
        end

        # Emitted only once the claim is held. Emitting at creation would queue a
        # session_started for a row the lost-claim path then destroys, and that
        # event is already on its way to external destinations.
        emit_session_started(session)
        session
      end

      # Returns nil when the winner has not written its state yet, and the call
      # then goes unaudited rather than retrying: waiting would mean sleeping in
      # a webserver thread, which is the same reason
      # `Gitlab::ExclusiveLease#in_lock` is avoided above.
      def resume_after_lost_claim
        state = read_state
        return unless state

        ::Ai::Governance::Session.find_by_id(state['session_id'])
      end

      # `external_xid` is minted here rather than read off the request: the
      # protocol carries no session identifier, so GitLab is the only party that
      # can name this session. `ExactlyOnePresentValidator` on the model requires
      # it, because an MCP session has no `Ai::DuoWorkflows::Workflow` behind it.
      def create_session
        ::Ai::Governance::Session.create!(
          namespace_id: namespace_id,
          project_id: project&.id,
          user_id: current_user.id,
          external_xid: SecureRandom.uuid,
          source: :mcp,
          status: :running,
          session_started_at: Time.current,
          agent_type: agent_name
        )
      end

      def claim(session)
        started_at = session.session_started_at.to_i

        with_redis do |redis|
          claimed = redis.set(lookup_key, payload(session, started_at), nx: true, ex: ttl_seconds(started_at))
          redis.zadd(OPEN_SESSIONS_KEY, expires_at(started_at), session.id) if claimed
          claimed
        end
      end

      def write_state(session, started_at:)
        with_redis do |redis|
          redis.set(lookup_key, payload(session, started_at), ex: ttl_seconds(started_at))
          redis.zadd(OPEN_SESSIONS_KEY, expires_at(started_at), session.id)
        end
      end

      def payload(session, started_at)
        ::Gitlab::Json.dump(
          session_id: session.id,
          started_at: started_at,
          expires_at: expires_at(started_at)
        )
      end

      # The idle extension never pushes a session past its absolute cap, so a
      # continuously active agent rolls into a fresh session every MAX_DURATION.
      def expires_at(started_at)
        [Time.current + IDLE_EXTENSION, Time.zone.at(started_at) + MAX_DURATION].min.to_i
      end

      def ttl_seconds(started_at)
        [expires_at(started_at) - Time.current.to_i, 1].max
      end

      # The OAuth application name is declared by the client at registration and
      # is never verified, so it is mapped onto a known slug rather than stored
      # verbatim. An unrecognised name becomes `unknown`, which keeps an arbitrary
      # caller-supplied label out of the `agent_type` dimension. The raw claim
      # stays recoverable through `oauth_application_id` in the event details.
      def agent_name
        return UNKNOWN_AGENT unless application_id

        declared = ::Authn::OauthApplication.find_by_id(application_id)&.name.to_s

        slug_for(declared.delete_prefix(DYNAMIC_APP_NAME_PREFIX))
      end
      strong_memoize_attr :agent_name

      def slug_for(declared)
        AGENT_PATTERNS.each { |slug, pattern| return slug if pattern.match?(declared) }

        UNKNOWN_AGENT
      end

      def emit_session_started(session)
        ::Mcp::Audit::CaptureEventService.new(
          current_user: current_user,
          session: session,
          kind: :session_started
        ).execute
      end

      def with_redis(&block)
        # rubocop:disable CodeReuse/ActiveRecord -- Redis connection pool, not ActiveRecord
        ::Gitlab::Redis::SharedState.with(&block)
        # rubocop:enable CodeReuse/ActiveRecord
      end
    end
  end
end
