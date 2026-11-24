# frozen_string_literal: true

module EE
  module JwksController
    extend ::Gitlab::Utils::Override

    private

    override :load_keys
    def load_keys
      super + CloudConnector::Keys.all_as_pem
    end
  end
end
