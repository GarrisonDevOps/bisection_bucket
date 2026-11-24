# frozen_string_literal: true

module EE
  module SearchServicePresenter
    extend ::Gitlab::Utils::Override

    override :advanced_search_enabled?
    def advanced_search_enabled?
      search_service.use_elasticsearch?
    end

    override :zoekt_enabled?
    def zoekt_enabled?
      search_service.use_zoekt?
    end
  end
end
