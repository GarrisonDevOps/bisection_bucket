# frozen_string_literal: true

module Projects
  class LogsController < Projects::ApplicationController
    feature_category :observability

    before_action :authorize_read_observability!

    def index; end
  end
end
