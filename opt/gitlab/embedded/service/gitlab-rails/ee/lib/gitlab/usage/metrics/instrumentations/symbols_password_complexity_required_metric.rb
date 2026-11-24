# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class SymbolsPasswordComplexityRequiredMetric < GenericMetric
          value do
            Gitlab::CurrentSettings.password_symbol_required
          end
        end
      end
    end
  end
end
