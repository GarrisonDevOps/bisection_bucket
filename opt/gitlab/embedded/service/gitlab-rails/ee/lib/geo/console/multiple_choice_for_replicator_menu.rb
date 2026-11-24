# frozen_string_literal: true

module Geo
  module Console
    class MultipleChoiceForReplicatorMenu < MultipleChoiceMenu
      def initialize(replicator_class:, referer: nil, input_stream: $stdin, output_stream: $stdout)
        @input_stream = input_stream
        @output_stream = output_stream
        @referer = referer
        @replicator_class = replicator_class
      end
    end
  end
end
