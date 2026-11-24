# frozen_string_literal: true

class Groups::Analytics::CycleAnalytics::ValueStreamsController < Groups::Analytics::ApplicationController
  include ::Analytics::CycleAnalytics::ValueStreamActions

  respond_to :json

  before_action :value_stream, only: %i[show edit update]

  layout 'group'

  private

  def namespace
    @group
  end
end
