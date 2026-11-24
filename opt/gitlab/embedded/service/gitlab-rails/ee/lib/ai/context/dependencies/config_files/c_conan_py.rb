# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        class CConanPy < CppConanPy
          def self.lang_name
            'C'
          end
        end
      end
    end
  end
end
