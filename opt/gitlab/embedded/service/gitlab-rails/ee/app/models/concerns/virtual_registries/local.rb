# frozen_string_literal: true

module VirtualRegistries
  module Local
    extend ActiveSupport::Concern

    def local?
      true
    end

    def remote?
      false
    end

    def upstream_type
      'local'
    end
  end
end
