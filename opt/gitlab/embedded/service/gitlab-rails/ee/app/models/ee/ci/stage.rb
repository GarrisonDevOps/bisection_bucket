# frozen_string_literal: true

module EE
  module Ci
    module Stage
      include ::Gitlab::Utils::StrongMemoize

      def reserved_pre?
        name == ::Gitlab::Ci::Config::Stages::RESERVED_POLICY_PRE
      end
      strong_memoize_attr :reserved_pre?
    end
  end
end
