# frozen_string_literal: true

module API
  module Entities
    module Ml
      module Mlflow
        class ListExperiment < Grape::Entity
          expose :experiments, using: ::API::Entities::Ml::Mlflow::Experiment, documentation: { is_array: true }
          expose :next_page_token, if: ->(response, _options) { response.key?(:next_page_token) },
            documentation: { type: 'String', desc: 'Returned when the response is paginated' }
        end
      end
    end
  end
end
