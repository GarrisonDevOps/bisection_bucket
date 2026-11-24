# frozen_string_literal: true

require "prometheus/client/formats/text"

module Labkit
  # Metrics provides functionality for producing metrics
  module Metrics
    autoload :Client, "labkit/metrics/client"
    autoload :RackExporter, "labkit/metrics/rack_exporter"
    autoload :Null, "labkit/metrics/null"

    class << self
      def prometheus_metrics_text
        dir = Client.configuration.multiprocess_files_dir
        ::Prometheus::Client::Formats::Text.marshal_multiprocess(dir)
      end
    end
  end
end
