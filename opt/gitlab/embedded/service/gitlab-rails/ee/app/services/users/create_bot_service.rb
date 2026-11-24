# frozen_string_literal: true

module Users
  class CreateBotService < CreateService
    extend ::Gitlab::Utils::Override

    private

    override :build_class
    def build_class
      Users::BuildBotService
    end
  end
end
