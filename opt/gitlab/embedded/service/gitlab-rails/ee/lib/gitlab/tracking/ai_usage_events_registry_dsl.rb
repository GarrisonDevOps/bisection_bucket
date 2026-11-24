# frozen_string_literal: true

module Gitlab
  module Tracking
    # rubocop:disable Gitlab/ModuleWithInstanceVariables -- it's a class level DSL. It's intended to be a module.
    module AiUsageEventsRegistryDsl
      def register_feature(name, &block)
        guard_absent_feature!
        @registered_events ||= {}.with_indifferent_access
        @current_feature = name
        instance_eval(&block)
        @current_feature = nil
      end

      def events(names_with_ids, &event_transformation)
        guard_present_feature!

        names_with_ids.each do |name, id|
          guard_internal_event_existence!(name)
          guard_duplicated_event!(name, id)
          @registered_events[name] = {
            id: id,
            transformations: [],
            feature: @current_feature
          }
          transformation(name, &event_transformation)
        end
      end

      def deprecated_events(names_with_ids)
        guard_present_feature!

        names_with_ids.each do |name, id|
          guard_duplicated_event!(name, id)
          @registered_events[name] = {
            id: id,
            transformations: [],
            deprecated: true,
            feature: @current_feature
          }
        end
      end

      def non_user_action_events(*names)
        guard_present_feature!

        names.each do |name|
          @registered_events.fetch(name)[:non_user_action] = true
        end
      end

      def transformation(*names, &block)
        return unless block

        names.each do |name|
          @registered_events[name][:transformations] << block
        end
      end

      def registered_events(feature = nil)
        return {} unless @registered_events

        events = @registered_events
        events = events.select { |_name, event| event[:feature] == feature } if feature

        events.transform_values { |options| options[:id] }
      end

      def registered_user_action_events(feature = nil)
        registered_events(feature).reject { |name, _id| non_user_action_event?(name) }
      end

      def registered_transformations(event_name)
        return [] unless @registered_events

        @registered_events[event_name]&.fetch(:transformations)
      end

      def non_user_action_event?(event_name)
        return false unless @registered_events && @registered_events[event_name]

        @registered_events[event_name][:non_user_action] == true
      end

      def deprecated_event?(event_name)
        return false unless @registered_events && @registered_events[event_name]

        @registered_events[event_name][:deprecated]
      end

      def registered_features
        return [] unless @registered_events

        @registered_events.values.pluck(:feature).uniq.compact # rubocop:disable CodeReuse/ActiveRecord -- it's a hash.
      end

      private

      def guard_internal_event_existence!(event_name)
        return if Gitlab::Tracking::EventDefinition.internal_event_exists?(event_name.to_s)

        raise "Event `#{event_name}` is not defined in InternalEvents"
      end

      def guard_duplicated_event!(name, id)
        raise "Event with name `#{name}` was already registered" if @registered_events[name]
        raise "Event with id `#{id}` was already registered" if @registered_events.detect { |_n, e| e[:id] == id }
      end

      def guard_present_feature!
        return if @current_feature

        raise "Cannot register events outside of a feature context. Use register_feature method."
      end

      def guard_absent_feature!
        return unless @current_feature

        raise "Nested features are not supported. Use register_feature method on top level."
      end
    end
    # rubocop:enable Gitlab/ModuleWithInstanceVariables
  end
end
