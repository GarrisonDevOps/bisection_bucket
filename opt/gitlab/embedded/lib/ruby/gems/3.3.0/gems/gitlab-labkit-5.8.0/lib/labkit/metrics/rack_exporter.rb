# frozen_string_literal: true

require "prometheus/client/rack/exporter"

module Labkit
  module Metrics
    # A wrapper around the Rack exporter middleware provided by
    # prometheus-client-mmap gem
    # https://gitlab.com/gitlab-org/ruby/gems/prometheus-client-mmap
    class RackExporter < Prometheus::Client::Rack::Exporter; end
  end
end
