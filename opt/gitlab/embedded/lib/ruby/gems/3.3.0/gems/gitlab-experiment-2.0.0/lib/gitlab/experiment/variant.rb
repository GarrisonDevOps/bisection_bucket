# frozen_string_literal: true

module Gitlab
  class Experiment
    Variant = Struct.new(:name, :payload, keyword_init: true) do
      def group
        name == 'control' ? :control : :experiment
      end
    end
  end
end
