# frozen_string_literal: true

class CountryStatesController < ActionController::Metal
  include AbstractController::Rendering
  include ActionController::ApiRendering
  include ActionController::Renderers
  include ActionController::StrongParameters

  use_renderers :json

  def index
    states = World.states_for_country(country_param)

    render json: states, status: (states ? :ok : :not_found)
  end

  private

  def country_param
    params.permit(:country)[:country]
  end
end
