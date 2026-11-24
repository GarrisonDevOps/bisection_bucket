# frozen_string_literal: true

require_relative "version"
require_relative "current_user"
require 'snowplow-tracker'

module GitlabSDK
  class Client
    SCHEMAS = {
      custom_event: 'iglu:com.gitlab/custom_event/jsonschema/1-0-0',
      user_context: 'iglu:com.gitlab/user_context/jsonschema/1-0-0'
    }.freeze
    DEFAULT_TRACKER_NAMESPACE = 'gitlab'
    USERAGENT = "GitLab Analytics Ruby SDK/#{GitlabSDK::VERSION}"

    HostHasNoSchemeError = Class.new(StandardError)

    def initialize(app_id:, host:, buffer_size: 1, async: true)
      emitter = build_emitter(host, buffer_size: buffer_size, async: async)

      @tracker = SnowplowTracker::Tracker.new(
        emitters: emitter,
        app_id: app_id,
        namespace: DEFAULT_TRACKER_NAMESPACE
      )
    end

    def track(event_name, event_payload = {})
      self_desc_json = SnowplowTracker::SelfDescribingJson.new(
        SCHEMAS[:custom_event],
        name: event_name,
        props: event_payload
      )

      track_arguments = { event_json: self_desc_json }

      set_subject_data
      set_user_context(track_arguments)

      tracker.track_self_describing_event(**track_arguments)
    end

    def identify(user_id, user_attributes = {})
      GitlabSDK::CurrentUser.user_id = user_id
      GitlabSDK::CurrentUser.user_attributes = user_attributes
    end

    def flush_events(async: false)
      tracker.flush(async: async)
    end

    private

    attr_reader :tracker

    def build_emitter(host, buffer_size:, async:)
      uri = URI(host)
      raise HostHasNoSchemeError unless uri.scheme
      raise ArgumentError, 'buffer_size has to be positive' unless buffer_size.positive?

      endpoint = "#{uri.hostname}:#{uri.port}#{uri.path}"
      method = buffer_size > 1 ? 'post' : 'get'
      emitter_class = async ? SnowplowTracker::AsyncEmitter : SnowplowTracker::Emitter

      emitter_class.new(
        endpoint: endpoint,
        options: {
          protocol: uri.scheme,
          method: method,
          buffer_size: buffer_size
        }
      )
    end

    def set_subject_data
      subject = SnowplowTracker::Subject.new

      set_user_id_on_subject(subject)
      subject.set_useragent(USERAGENT)

      tracker.set_subject(subject)
    end

    def set_user_id_on_subject(subject)
      user_id = GitlabSDK::CurrentUser.user_id

      subject.set_user_id(user_id) if user_id
    end

    def set_user_context(track_arguments)
      user_attributes = GitlabSDK::CurrentUser.user_attributes || {}

      return if user_attributes.empty?

      user_context = SnowplowTracker::SelfDescribingJson.new(
        SCHEMAS[:user_context],
        user_attributes
      )
      track_arguments[:context] = [user_context]
    end
  end
end
