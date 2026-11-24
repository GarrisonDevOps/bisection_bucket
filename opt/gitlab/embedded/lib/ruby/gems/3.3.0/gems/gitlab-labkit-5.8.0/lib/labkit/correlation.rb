# frozen_string_literal: true

module Labkit
  # Correlation provides correlation functionality
  module Correlation
    autoload :GRPC, "labkit/correlation/grpc"

    autoload :CorrelationId, "labkit/correlation/correlation_id"
  end
end
