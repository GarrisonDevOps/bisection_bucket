# frozen_string_literal: true

module Gitlab
  module Tracking
    module ActivationTracking
      def self.track_event(event_name, **kwargs)
        namespace = kwargs[:namespace] || kwargs[:project]&.namespace

        Activation::Metric.track(event_name.to_sym, user: kwargs[:user], namespace: namespace)
      end
    end
  end
end
