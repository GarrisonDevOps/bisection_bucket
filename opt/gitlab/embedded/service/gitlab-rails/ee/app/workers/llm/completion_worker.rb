# frozen_string_literal: true

module Llm
  class CompletionWorker
    include ApplicationWorker

    idempotent!
    feature_category :ai_abstraction_layer
    urgency :low
    data_consistency :sticky
    worker_has_external_dependencies!
    deduplicate :until_executed
    sidekiq_options retry: 3

    class << self
      def serialize_message(message)
        message.to_h.tap do |hash|
          hash['user'] &&= hash['user'].to_gid
          hash['context'] = hash['context'].to_h
          resource = hash['context']['resource']
          project = resource.project if resource.respond_to?(:project)
          hash['context']['project'] = project.to_gid if project
          hash['context']['resource'] &&= hash['context']['resource'].to_gid
          hash['thread_id'] = hash['thread'].id if hash['thread']
        end.as_json
      end

      def deserialize_message(message_hash, options)
        message_hash['user'] = User.find_by_id(GitlabSchema.parse_gid(message_hash['user']).model_id)
        return unless message_hash['user']

        message_hash['context'] = begin
          message_hash['context']['resource'] &&= resource(message_hash)
          ::Gitlab::Llm::AiMessageContext.new(message_hash['context'])
        end

        if message_hash['thread_id']
          message_hash['thread'] = message_hash['user'].ai_conversation_threads.find_by_id(message_hash['thread_id'])

          return unless message_hash['thread']
        end

        ::Gitlab::Llm::AiMessage.for(action: message_hash['ai_action']).new(options.merge(message_hash))
      end

      def perform_for(message, options = {})
        # set SESSION_ID_HASH_KEY to ensure inside Sidekiq `Gitlab::Session.current` is not nil
        with_ip_address_state.set(
          Gitlab::SidekiqMiddleware::SetSession::Server::SESSION_ID_HASH_KEY => ::Gitlab::Session.session_id_for_worker
        ).perform_async(serialize_message(message), options.as_json)
      end

      def resource(message_hash)
        resource_gid = GitlabSchema.parse_gid(message_hash['context']['resource'])
        return resource_gid.model_class.find_by_id(resource_gid.model_id) unless resource_gid.model_class == Commit

        project = Project.find_by_id(GitlabSchema.parse_gid(message_hash['context']['project']).model_id)
        project&.commit_by(oid: resource_gid.model_id)
      end
    end

    def perform(prompt_message_hash, options = {})
      ai_prompt_message = self.class.deserialize_message(prompt_message_hash, options)
      unless ai_prompt_message
        log_extra_metadata_on_done(:skipped, 'user_or_thread_not_found')
        return
      end

      # set warden to ensure SsoEnforcer#in_context_of_user_web_activity? returns true
      session = Gitlab::Session.current
      if session && !session.key?('warden.user.user.key')
        session['warden.user.user.key'] = User.serialize_into_session(ai_prompt_message.user)
      end

      Gitlab::Llm::Tracking.event_for_ai_message(
        self.class.to_s, "perform_completion_worker", ai_message: ai_prompt_message
      )
      Gitlab::Tracking::AiTracking.track_user_activity(ai_prompt_message.user)

      Internal::CompletionService.new(ai_prompt_message, options).execute
    ensure
      log_extra_metadata_on_done(:ai_action, ai_prompt_message.ai_action) if ai_prompt_message
    end
  end
end
