# frozen_string_literal: true

module Gitlab
  module Ci
    module Reports
      module Sbom
        class License
          attr_accessor :spdx_identifier, :name, :url, :expression

          def initialize(spdx_identifier: nil, name: nil, url: nil, expression: nil)
            @spdx_identifier = spdx_identifier
            @name = name
            @url = url
            @expression = expression
          end
        end
      end
    end
  end
end
